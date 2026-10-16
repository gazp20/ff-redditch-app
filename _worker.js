export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/cdn-cgi/")) {
      return env.ASSETS.fetch(request);
    }

    const json = (data, status = 200) =>
      new Response(JSON.stringify(data), {
        status,
        headers: {
          "content-type": "application/json; charset=UTF-8",
          "cache-control": "no-store"
        }
      });

    function getAccessEmail() {
      const accessJwt = request.headers.get("Cf-Access-Jwt-Assertion");
      if (!accessJwt) return "";

      try {
        const payloadPart = accessJwt.split(".")[1];
        const base64 = payloadPart.replace(/-/g, "+").replace(/_/g, "/");
        const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
        const payload = JSON.parse(atob(padded));

        return String(payload.email || payload.sub || "")
          .trim()
          .toLowerCase();
      } catch (error) {
        return "";
      }
    }

    function backendConfigured() {
      return Boolean(env.MEMBERS_API_URL && env.MEMBERS_API_SECRET);
    }

    async function callMembersApi(payload) {
      if (!backendConfigured()) {
        return {
          ok: false,
          status: 500,
          body: JSON.stringify({
            success: false,
            error: "Members API is not configured"
          })
        };
      }

      try {
        const response = await fetch(
          String(env.MEMBERS_API_URL).trim(),
          {
            method: "POST",
            headers: {
              "accept": "application/json",
              "content-type": "application/json"
            },
            body: JSON.stringify({
              ...payload,
              key: String(env.MEMBERS_API_SECRET).trim()
            })
          }
        );

        return {
          ok: response.ok,
          status: response.status,
          body: await response.text()
        };
      } catch (error) {
        return {
          ok: false,
          status: 502,
          body: JSON.stringify({
            success: false,
            error: "Could not reach members database"
          })
        };
      }
    }

    // STRIPE SANDBOX. Requires a Cloudflare Access JWT verified against Access JWKS.
    async function verifiedPaymentEmail(){
      const jwt=request.headers.get("Cf-Access-Jwt-Assertion")||"";
      const configuredTeam=String(env.CF_ACCESS_TEAM_DOMAIN||"").trim().replace(/\/$/,"");
      const team=/^https?:\/\//i.test(configuredTeam)?configuredTeam:"https://"+configuredTeam;
      const aud=String(env.CF_ACCESS_AUD||"");
      if(!jwt||!/^https:\/\/[a-z0-9.-]+\.cloudflareaccess\.com$/i.test(team)||!aud)return "";
      try{
        const [head,payload,signature]=jwt.split(".");if(!signature)return "";
        const decode=x=>Uint8Array.from(atob(x.replace(/-/g,"+").replace(/_/g,"/")+"=".repeat((4-x.length%4)%4)),c=>c.charCodeAt(0));
        const header=JSON.parse(new TextDecoder().decode(decode(head)));
        const claims=JSON.parse(new TextDecoder().decode(decode(payload)));
        if(header.alg!=="RS256"||!header.kid||claims.iss!==team||!(Array.isArray(claims.aud)?claims.aud.includes(aud):claims.aud===aud)||Number(claims.exp)*1000<Date.now()||Number(claims.nbf||0)*1000>Date.now()+60000)return "";
        const jwksRes=await fetch(team+"/cdn-cgi/access/certs");if(!jwksRes.ok)return "";
        const jwks=await jwksRes.json(),jwk=(jwks.keys||[]).find(k=>k.kid===header.kid);if(!jwk)return "";
        const key=await crypto.subtle.importKey("jwk",jwk,{name:"RSASSA-PKCS1-v1_5",hash:"SHA-256"},false,["verify"]);
        const ok=await crypto.subtle.verify("RSASSA-PKCS1-v1_5",key,decode(signature),new TextEncoder().encode(head+"."+payload));
        return ok?String(claims.email||"").trim().toLowerCase():"";
      }catch(e){return "";}
    }
    async function stripeApi(path,params){
      const form=new URLSearchParams();for(const [k,v] of Object.entries(params))form.append(k,String(v));
      const r=await fetch("https://api.stripe.com/v1/"+path,{method:"POST",headers:{"Authorization":"Bearer "+env.STRIPE_SECRET_KEY,"Content-Type":"application/x-www-form-urlencoded"},body:form.toString()});
      const data=await r.json();if(!r.ok)throw Error(data.error?.message||"Stripe request failed");return data;
    }
    async function validStripeSignature(raw,header){
      const pieces=String(header||"").split(","),timestamp=pieces.find(x=>x.startsWith("t="))?.slice(2),signatures=pieces.filter(x=>x.startsWith("v1=")).map(x=>x.slice(3));
      if(!timestamp||Math.abs(Date.now()/1000-Number(timestamp))>300||!signatures.length)return false;
      const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(env.STRIPE_WEBHOOK_SECRET),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
      const sig=new Uint8Array(await crypto.subtle.sign("HMAC",key,new TextEncoder().encode(timestamp+"."+raw)));
      const hex=[...sig].map(b=>b.toString(16).padStart(2,"0")).join("");return signatures.some(x=>x===hex);
    }
    if(url.pathname==="/api/stripe/webhook"){
      if(request.method!=="POST")return json({success:false},405);
      if(!env.STRIPE_WEBHOOK_SECRET||!env.STRIPE_SECRET_KEY)return json({success:false,error:"Stripe not configured"},503);
      const raw=await request.text();if(!await validStripeSignature(raw,request.headers.get("Stripe-Signature")))return json({success:false,error:"Invalid Stripe signature"},400);
      const event=JSON.parse(raw);if(event.type!=="checkout.session.completed")return json({received:true});
      const session=event.data?.object||{};
      if(session.mode!=="payment"||session.payment_status!=="paid"||!String(session.id).startsWith("cs_test_")||session.currency!=="gbp"||!session.metadata?.ffr_intent_id)return json({received:true});
      const result=await callMembersApi({action:"stripe_complete",intentId:session.metadata.ffr_intent_id,sessionId:session.id,amountPence:session.amount_total,currency:session.currency});
      let parsed={};try{parsed=JSON.parse(result.body);}catch(e){}
      if(!result.ok||!parsed.success)return json({success:false,error:"Ledger update failed; Stripe will retry"},500);
      return json({received:true});
    }
    if(url.pathname==="/api/payments/checkout"){
      if(request.method!=="POST")return json({success:false,error:"POST required"},405);
      if(!env.STRIPE_SECRET_KEY||!String(env.STRIPE_SECRET_KEY).startsWith("sk_test_"))return json({success:false,error:"Stripe Sandbox not configured"},503);
      const email=await verifiedPaymentEmail();if(!email)return json({success:false,error:"Verified Cloudflare Access login required"},401);
      const prepared=await callMembersApi({action:"stripe_prepare",email});let p={};try{p=JSON.parse(prepared.body);}catch(e){}
      if(!prepared.ok||!p.success)return json({success:false,error:p.error||"Could not prepare checkout"},409);
      try{
        const checkout=await stripeApi("checkout/sessions",{
          mode:"payment", "payment_method_types[0]":"card", "line_items[0][price_data][currency]":"gbp", "line_items[0][price_data][unit_amount]":p.amountPence,
          "line_items[0][price_data][product_data][name]":"FF Redditch account balance", "line_items[0][quantity]":1,
          "client_reference_id":p.intentId,"metadata[ffr_intent_id]":p.intentId,"customer_email":email,
          "success_url":url.origin+"/?stripe=success", "cancel_url":url.origin+"/?stripe=cancel",
          "expires_at":Math.floor(Date.now()/1000)+1800
        });
        if(!String(checkout.id||"").startsWith("cs_test_")||!String(checkout.url||"").startsWith("https://checkout.stripe.com/"))throw Error("Sandbox checkout validation failed");
        const attached=await callMembersApi({action:"stripe_attach",intentId:p.intentId,sessionId:checkout.id});let a={};try{a=JSON.parse(attached.body);}catch(e){}
        if(!attached.ok||!a.success)throw Error("Checkout session could not be registered");
        return json({success:true,url:checkout.url});
      }catch(e){await callMembersApi({action:"stripe_abort",intentId:p.intentId});return json({success:false,error:"Unable to create checkout. Please try again."},502);}
    }

    if (
      url.pathname === "/api/me" ||
      url.pathname === "/api/me/"
    ) {
      const email = getAccessEmail();

      if (!email) {
        return json({
          success: false,
          error: "Authenticated member email not found"
        }, 401);
      }

      const result = await callMembersApi({ email });

      return new Response(result.body, {
        status: result.status,
        headers: {
          "content-type": "application/json; charset=UTF-8",
          "cache-control": "no-store"
        }
      });
    }

    if (
      url.pathname === "/api/rankings" ||
      url.pathname === "/api/rankings/"
    ) {
      const result = await callMembersApi({
        action: "rankings"
      });

      return new Response(result.body, {
        status: result.status,
        headers: {
          "content-type": "application/json; charset=UTF-8",
          "cache-control": "no-store"
        }
      });
    }


    if (
      url.pathname === "/api/club-news" ||
      url.pathname === "/api/club-news/"
    ) {
      const result=await callMembersApi({action:"club_news"});
      return new Response(result.body,{status:result.status,headers:{"content-type":"application/json; charset=UTF-8","cache-control":"no-store"}});
    }


    if (
      url.pathname === "/api/fixtures" ||
      url.pathname === "/api/fixtures/"
    ) {
      const email = getAccessEmail();

      if (!email) {
        return json({
          success: false,
          error: "Authenticated member email not found"
        }, 401);
      }

      const result = await callMembersApi({
        action: "fixtures",
        email
      });

      return new Response(result.body, {
        status: result.status,
        headers: {
          "content-type": "application/json; charset=UTF-8",
          "cache-control": "no-store"
        }
      });
    }



    if (
      url.pathname === "/api/11s/admin" ||
      url.pathname === "/api/11s/admin/"
    ) {
      const email = getAccessEmail();

      if (!email) {
        return json({
          success: false,
          error: "Authenticated member email not found"
        }, 401);
      }

      const result = await callMembersApi({
        action: "11s_admin_availability",
        email
      });

      return new Response(result.body, {
        status: result.status,
        headers: {
          "content-type": "application/json; charset=UTF-8",
          "cache-control": "no-store"
        }
      });
    }


    if (
      url.pathname === "/api/11s/squad" ||
      url.pathname === "/api/11s/squad/"
    ) {
      if (request.method !== "POST") {
        return json({
          success: false,
          error: "POST required"
        }, 405);
      }

      const email = getAccessEmail();

      if (!email) {
        return json({
          success: false,
          error: "Authenticated member email not found"
        }, 401);
      }

      let input = {};

      try {
        input = await request.json();
      } catch (error) {
        return json({
          success: false,
          error: "Invalid JSON"
        }, 400);
      }

      const result = await callMembersApi({
        action: "11s_save_squad",
        email,
        fixtureId: input.fixtureId || "",
        selectedEmails:Array.isArray(input.selectedEmails)?input.selectedEmails:[],
        reserveEmails:Array.isArray(input.reserveEmails)?input.reserveEmails:[],
        published:input.published===true
      });

      return new Response(result.body, {
        status: result.status,
        headers: {
          "content-type": "application/json; charset=UTF-8",
          "cache-control": "no-store"
        }
      });
    }

    if (
      url.pathname === "/api/11s/subs" ||
      url.pathname === "/api/11s/subs/"
    ) {
      const email = getAccessEmail();

      if (!email) {
        return json({
          success: false,
          error: "Authenticated member email not found"
        }, 401);
      }

      const result = await callMembersApi({
        action: "11s_my_subs",
        email
      });

      return new Response(result.body, {
        status: result.status,
        headers: {
          "content-type": "application/json; charset=UTF-8",
          "cache-control": "no-store"
        }
      });
    }

    if (
      url.pathname === "/api/11s/respond" ||
      url.pathname === "/api/11s/respond/"
    ) {
      const email = getAccessEmail();

      if (!email) {
        return json({
          success: false,
          error: "Authenticated member email not found"
        }, 401);
      }

      if (request.method !== "POST") {
        return new Response(
          JSON.stringify({
            success: false,
            error: "Method not allowed"
          }),
          {
            status: 405,
            headers: {
              "content-type": "application/json; charset=UTF-8"
            }
          }
        );
      }

      const input = await request.json();

      const result = await callMembersApi({
        action: "11s_set_availability",
        email,
        fixtureId: input.fixtureId || "",
        response: input.response || ""
      });

      return new Response(result.body, {
        status: result.status,
        headers: {
          "content-type": "application/json; charset=UTF-8",
          "cache-control": "no-store"
        }
      });
    }

    if (url.pathname === "/api/payments" || url.pathname === "/api/payments/") {
      const email=getAccessEmail(); if(!email)return json({success:false,error:"Authenticated member email not found"},401);
      const result=await callMembersApi({action:"payments_my",email});let data={};try{data=JSON.parse(result.body);}catch(e){}data.stripeEnabled=Boolean(env.STRIPE_SECRET_KEY&&String(env.STRIPE_SECRET_KEY).startsWith("sk_test_")&&env.STRIPE_WEBHOOK_SECRET&&env.CF_ACCESS_TEAM_DOMAIN&&env.CF_ACCESS_AUD);return json(data,result.status);
    }
    if (url.pathname === "/api/payments/admin" || url.pathname === "/api/payments/admin/") {
      const email=getAccessEmail(); if(!email)return json({success:false,error:"Authenticated member email not found"},401);
      const result=await callMembersApi({action:"payments_admin",email});return new Response(result.body,{status:result.status,headers:{"content-type":"application/json; charset=UTF-8","cache-control":"no-store"}});
    }
    if (url.pathname === "/api/payments/fine" || url.pathname === "/api/payments/fine/") {
      if(request.method!=="POST")return json({success:false,error:"POST required"},405);const email=getAccessEmail();if(!email)return json({success:false,error:"Authenticated member email not found"},401);let input={};try{input=await request.json();}catch(e){return json({success:false,error:"Invalid JSON"},400);}
      const result=await callMembersApi({action:"payments_add_fine",email,playerEmail:input.playerEmail||"",description:input.description||"",amount:Number(input.amount||0)});return new Response(result.body,{status:result.status,headers:{"content-type":"application/json; charset=UTF-8","cache-control":"no-store"}});
    }
    if (url.pathname === "/api/payments/status" || url.pathname === "/api/payments/status/") {
      if(request.method!=="POST")return json({success:false,error:"POST required"},405);const email=getAccessEmail();if(!email)return json({success:false,error:"Authenticated member email not found"},401);let input={};try{input=await request.json();}catch(e){return json({success:false,error:"Invalid JSON"},400);}
      const result=await callMembersApi({action:"payments_settle",email,chargeId:input.chargeId||"",command:input.action||""});return new Response(result.body,{status:result.status,headers:{"content-type":"application/json; charset=UTF-8","cache-control":"no-store"}});
    }

    if (
      url.pathname === "/api/tnf/next" ||
      url.pathname === "/api/tnf/next/"
    ) {
      const email = getAccessEmail();

      if (!email) {
        return json({
          success: false,
          error: "Authenticated member email not found"
        }, 401);
      }

      const result = await callMembersApi({
        action: "tnf_next_session",
        email
      });

      return new Response(result.body, {
        status: result.status,
        headers: {
          "content-type": "application/json; charset=UTF-8",
          "cache-control": "no-store"
        }
      });
    }


    if (
      url.pathname === "/api/tnf/admin" ||
      url.pathname === "/api/tnf/admin/"
    ) {
      const email = getAccessEmail();

      if (!email) {
        return json({
          success: false,
          error: "Authenticated member email not found"
        }, 401);
      }

      const result = await callMembersApi({
        action: "tnf_admin_teams",
        email
      });

      return new Response(result.body, {
        status: result.status,
        headers: {
          "content-type": "application/json; charset=UTF-8",
          "cache-control": "no-store"
        }
      });
    }

    if (
      url.pathname === "/api/tnf/teams" ||
      url.pathname === "/api/tnf/teams/"
    ) {
      if (request.method !== "POST") {
        return json({
          success: false,
          error: "POST required"
        }, 405);
      }

      const email = getAccessEmail();

      if (!email) {
        return json({
          success: false,
          error: "Authenticated member email not found"
        }, 401);
      }

      let body = {};

      try {
        body = await request.json();
      } catch (error) {
        return json({
          success: false,
          error: "Invalid JSON"
        }, 400);
      }

      const result = await callMembersApi({
        action: "tnf_save_teams",
        email,
        sessionId: body.sessionId || "",
        assignments: Array.isArray(body.assignments) ? body.assignments : [],
        published: body.published === true
      });

      return new Response(result.body, {
        status: result.status,
        headers: {
          "content-type": "application/json; charset=UTF-8",
          "cache-control": "no-store"
        }
      });
    }


    if (
      url.pathname === "/api/tnf/weighin" ||
      url.pathname === "/api/tnf/weighin/"
    ) {
      const email = getAccessEmail();

      if (!email) {
        return json({
          success: false,
          error: "Authenticated member email not found"
        }, 401);
      }

      const result = await callMembersApi({
        action: "tnf_weighin_admin",
        email
      });

      return new Response(result.body, {
        status: result.status,
        headers: {
          "content-type": "application/json; charset=UTF-8",
          "cache-control": "no-store"
        }
      });
    }

    if (
      url.pathname === "/api/tnf/results" ||
      url.pathname === "/api/tnf/results/"
    ) {
      if (request.method !== "POST") {
        return json({
          success: false,
          error: "POST required"
        }, 405);
      }

      const email = getAccessEmail();

      if (!email) {
        return json({
          success: false,
          error: "Authenticated member email not found"
        }, 401);
      }

      let body = {};

      try {
        body = await request.json();
      } catch (error) {
        return json({
          success: false,
          error: "Invalid JSON"
        }, 400);
      }

      const result = await callMembersApi({
        action: "tnf_publish_weekly_results",
        email,
        sessionId: body.sessionId || "",
        winningTeam: body.winningTeam || "",
        results: Array.isArray(body.results) ? body.results : []
      });

      return new Response(result.body, {
        status: result.status,
        headers: {
          "content-type": "application/json; charset=UTF-8",
          "cache-control": "no-store"
        }
      });
    }

    if (
      url.pathname === "/api/tnf/week" ||
      url.pathname === "/api/tnf/week/"
    ) {
      if (request.method !== "POST") {
        return json({
          success: false,
          error: "POST required"
        }, 405);
      }

      const email = getAccessEmail();

      if (!email) {
        return json({
          success: false,
          error: "Authenticated member email not found"
        }, 401);
      }

      let body = {};
      try {
        body = await request.json();
      } catch (error) {
        return json({
          success: false,
          error: "Invalid JSON"
        }, 400);
      }

      const command = String(body.action || "").trim().toLowerCase();

      if (command !== "next" && command !== "reset") {
        return json({
          success: false,
          error: "Action must be next or reset"
        }, 400);
      }

      const result = await callMembersApi({
        action: "tnf_week_control",
        email,
        command
      });

      return new Response(result.body, {
        status: result.status,
        headers: {
          "content-type": "application/json; charset=UTF-8",
          "cache-control": "no-store"
        }
      });
    }


    if (
      url.pathname === "/api/tnf/respond" ||
      url.pathname === "/api/tnf/respond/"
    ) {
      if (request.method !== "POST") {
        return json({
          success: false,
          error: "POST required"
        }, 405);
      }

      const email = getAccessEmail();

      if (!email) {
        return json({
          success: false,
          error: "Authenticated member email not found"
        }, 401);
      }

      let body = {};

      try {
        body = await request.json();
      } catch (error) {
        return json({
          success: false,
          error: "Invalid JSON"
        }, 400);
      }

      const sessionId = String(body.sessionId || "").trim();
      const response = String(body.response || "").trim().toUpperCase();

      if (!sessionId) {
        return json({
          success: false,
          error: "Session ID required"
        }, 400);
      }

      if (response !== "IN" && response !== "OUT") {
        return json({
          success: false,
          error: "Response must be IN or OUT"
        }, 400);
      }

      const result = await callMembersApi({
        action: "tnf_set_availability",
        email,
        sessionId,
        response
      });

      return new Response(result.body, {
        status: result.status,
        headers: {
          "content-type": "application/json; charset=UTF-8",
          "cache-control": "no-store"
        }
      });
    }

    return env.ASSETS.fetch(request);
  }
};
