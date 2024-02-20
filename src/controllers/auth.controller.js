const user = require("../models/user.model");
const { createToken } = require("../middlewares/auth");

const APIError = require("../utils/errors");
const Response = require("../utils/response");

const bcrypt = require("bcrypt");

const login = async (req, res) => {
  const { email, password } = req.body;

  const userInfo = await user.findOne({ email });

  if (!userInfo) throw new APIError("Email yada Şifre Hatalı!", 401);

  const comparePassword = await bcrypt.compare(password, userInfo.password);

  if (!comparePassword) throw new APIError("Email yada Şifre Hatalı!", 401);

  createToken(userInfo, res);
};

const register = async (req, res) => {
  const { email } = req.body;

  const userCheck = await user.findOne({ email });

  if (userCheck) {
    throw new APIError("Girmiş Olduğunuz Email Kullanımda!", 401);
  }

  req.body.password = await bcrypt.hash(req.body.password, 10);

  const userSave = new user(req.body);

  await userSave
    .save()
    .then((data) => {
      return new Response(data, "Kayıt Başarıyla Eklendi.").created(res);
    })
    .catch((err) => {
      throw new APIError("Kullanıcı Kayıt Edilemedi!", 400);
    });
};

const me = async (req, res) => {
  return new Response(req.user).success(res);
};

module.exports = {
  login,
  register,
  me,
};
