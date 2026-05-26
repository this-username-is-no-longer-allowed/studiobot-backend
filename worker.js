import { WorkflowEntrypoint } from 'cloudflare:workers';

export default {
  async fetch(request, env, ctx) {
    // Discord only sends POSTs
    if (request.method !== "POST") {
      return new Response("OK", { status: 200 });
    }

    // Required Discord headers
    const signature = request.headers.get("X-Signature-Ed25519");
    const timestamp = request.headers.get("X-Signature-Timestamp");

    if (!signature || !timestamp) {
      return new Response("Missing signature", { status: 401 });
    }

    // IMPORTANT: read raw body first
    const body = await request.text();

    // Verify request
    const isValid = await verifyDiscordRequest(
      body,
      signature,
      timestamp,
      env.DISCORD_PUBLIC_KEY
    );

    if (!isValid) {
      return new Response("Invalid request", { status: 401 });
    }

    const interaction = JSON.parse(body);

    function forwardInteractionPayload(payload) {
      console.log(JSON.stringify(payload));
    }

    if (interaction.type === 1) {
      return new Response(
        JSON.stringify({ type: 1 }),
        { headers: { "Content-Type": "application/json" } }
      );
    }

    if (interaction.type === 2) {
      let path = [interaction.data.name];
      let current = interaction.data;
      let options = [];

      while (current.options?.length) {
        const next = current.options.find(
          o => o.type === 1 || o.type === 2
        );

        if (!next) {
          options = current.options;
          break;
        }

        path.push(next.name);
        current = next;
      }

      path = path.join('/');
      options = Object.fromEntries(
        options.map(item => {
          if (item.type === 11) { // Attachment
            const attachment = interaction.data?.resolved?.attachments[item.value];
            delete attachment.id;
            delete attachment.proxy_url;
            
            return [item.name, attachment];
          }
          return [item.name, item.value];
        })
      );
      const payload = {
        type: 'slash',
        job: {
          name: path,
          id: interaction.id
        },
        displayName: (interaction?.member?.user?.global_name || interaction?.user?.global_name || interaction?.member?.user?.username || interaction?.user?.username).replace(/[\x00-\x08\x0e-\x1f\x21-\x2f\x3a-\x40\x5b-\x60\x7b-\xff]/gu, '\\$&'),
        webhookUrl: `https://discord.com/api/v10/webhooks/${interaction.application_id}/${interaction.token}`,
        userId: interaction?.member?.user?.id || interaction?.user?.id,
        inputs: options
      };

      ctx.waitUntil((async () => {
        if (!payload.job.name === 'msg') return;
        await fetch(`https://discord.com/api/v10/channels/${payload.inputs.channel}/messages`, {
          method: 'POST',
          headers: {
            Authorization: `Bot ${env.BOT_TOKEN}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            flags: 1 << 15,
            components: [
              {
                type: 10,
                content: payload.inputs.content
              }
            ]
          })
        });
      })());

      return new Response(
        JSON.stringify({ type: 4, data: { flags: 1 << 6, content: 'Sending...' } }),
        { headers: { "Content-Type": "application/json" } }
      );
    }

    if (interaction.type === 3) {
      const payload = {
        type: 'component',
        job: {
          name: interaction.data.custom_id,
          id: interaction.id
        },
        displayName: (interaction?.member?.user?.global_name || interaction?.user?.global_name || interaction?.member?.user?.username || interaction?.user?.username).replace(/[\x00-\x08\x0e-\x1f\x21-\x2f\x3a-\x40\x5b-\x60\x7b-\xff]/gu, '\\$&'),
        webhookUrl: `https://discord.com/api/v10/webhooks/${interaction.application_id}/${interaction.token}`,
        userId: interaction?.member?.user?.id || interaction?.user?.id,
        message: {
          flags: interaction.message.flags,
          content: interaction.message.content,
          attachments: interaction.message.attachments,
          embeds: interaction.message.embeds,
          components: interaction.message.components
        }
      };

      return new Response(
        JSON.stringify({ type: 6 }), // Deferred update
        { headers: { "Content-Type": "application/json" } }
      );
    }

    return new Response("Unhandled interaction", { status: 400 });
  }
};

async function verifyDiscordRequest(body, signature, timestamp, publicKey) {
  const encoder = new TextEncoder();

  const message = encoder.encode(timestamp + body);
  const sig = hexToUint8Array(signature);
  const key = hexToUint8Array(publicKey);

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "Ed25519", namedCurve: "Ed25519" },
    false,
    ["verify"]
  );

  return crypto.subtle.verify(
    "Ed25519",
    cryptoKey,
    sig,
    message
  );
}

function hexToUint8Array(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}
