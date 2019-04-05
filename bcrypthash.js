const bcrypt = require("bcrypt");
console.log(bcrypt.hashSync(process.env.t, 524288));