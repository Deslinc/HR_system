import Joi from 'joi';

const passwordRules = Joi.string()
  .min(8)
  .max(128)
  .pattern(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
    'password complexity'
  )
  .messages({
    'string.pattern.name':
      'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character (@$!%*?&)',
    'string.min': 'Password must be at least 8 characters',
    'string.max': 'Password cannot exceed 128 characters',
  });

// ── Admin Bootstrap ────────────────────────────────────────
export const adminRegisterSchema = Joi.object({
  firstName: Joi.string().trim().min(2).max(50).required(),
  lastName: Joi.string().trim().min(2).max(50).required(),
  email: Joi.string().email().lowercase().required(),
  password: passwordRules.required(),
  bootstrapSecret: Joi.string().required().messages({
    'any.required': 'Admin bootstrap secret is required',
  }),
});

// ── Login ──────────────────────────────────────────────────
export const loginSchema = Joi.object({
  email: Joi.string().email().lowercase().required(),
  password: Joi.string().required(),
});

// ── Create User (Admin invites a new user) ─────────────────
export const createUserSchema = Joi.object({
  firstName: Joi.string().trim().min(2).max(50).required(),
  lastName: Joi.string().trim().min(2).max(50).required(),
  email: Joi.string().email().lowercase().required(),
  role: Joi.string()
    .valid('hr_manager', 'finance_officer', 'department_head', 'employee', 'auditor')
    .required(),
});

// ── Set / Create Password (from invite link) ───────────────
export const setPasswordSchema = Joi.object({
  inviteToken: Joi.string().required(),
  password: passwordRules.required(),
  confirmPassword: Joi.any()
    .valid(Joi.ref('password'))
    .required()
    .messages({ 'any.only': 'Passwords do not match' }),
});

// ── Refresh Token ──────────────────────────────────────────
export const refreshTokenSchema = Joi.object({
  // Token can come from cookie (preferred) or body
  refreshToken: Joi.string().optional(),
});

// ── Change Password (authenticated) ───────────────────────
export const changePasswordSchema = Joi.object({
  currentPassword: Joi.string().required(),
  newPassword: passwordRules.required(),
  confirmNewPassword: Joi.any()
    .valid(Joi.ref('newPassword'))
    .required()
    .messages({ 'any.only': 'Passwords do not match' }),
});