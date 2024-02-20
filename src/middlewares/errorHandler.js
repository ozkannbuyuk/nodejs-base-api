const APIError = require("../utils/errors");

const errorHandlerMiddleware = (err, req, res, next) => {
  if (err instanceof APIError) {
    return res.status(err.statusCode || 400).json({
      success: false,
      message: err.message,
    });
  }

  return res.status(500).json({
    success: false,
    message: "Bir Hata ile Karşılaştık. Lütfen Apinizi Kontrol Ediniz!",
  });
};

module.exports = errorHandlerMiddleware;
