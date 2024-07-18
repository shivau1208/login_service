const { createClient } = require("redis");

const client = createClient ({
  url : process.env.REDISS_URL
});

client.on("error", function(err) {
  throw err;
});
(async ()=>{
  await client.connect()
})();

module.exports = client;