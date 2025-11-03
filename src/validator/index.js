import { body } from "express-validator";

export const userRegisterValidator = () => {
  return [
    body("email")
      .trim()
      .notEmpty()
      .withMessage("email is required")
      .isEmail()
      .withMessage("email is invalid"),
    body("username")
      .trim()
      .notEmpty()
      .withMessage("user name required")
      .isLowercase()
      .withMessage("username must be in lower case")
      .isLength({ min: 3 })
      .withMessage("username must be atleadt 3 charachter"),
    body("password").trim().notEmpty().withMessage("password is required"),
    body("fullName").optional().trim(),
  ];
};

export const userLoginValidator = () => {
  return [
    body("email").optional().isEmail().withMessage("email is invalid"),
    body("password").notEmpty().withMessage("password is required"),
  ];
};

export const userChangeCurrentPasswordValidator = () => {
  return [
    body("oldPassword").notEmpty().withMessage("old password is required"),
    body("newPassword").notEmpty().withMessage("new password is required"),
  ];
};

export const userForgotPasswordValidator = () => {
  return [
    body("email")
      .notEmpty()
      .withMessage("email is required")
      .isEmail()
      .withMessage("email is in valid"),
  ];
};

export const userResetForgotPasswordValidator = () => {
  return [body("newPassword").notEmpty().withMessage("password is required")];
};
