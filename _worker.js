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
        selectedEmails: Array.isArray(input.selectedEmails) ? input.selectedEmails : [],
        published: input.published === true
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
