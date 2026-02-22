import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const ROLES = [
  'admin',
  'hr_manager',
  'finance_officer',
  'department_head',
  'employee',
  'auditor',
];

const userSchema = new mongoose.Schema(
  {
    // ── Identity ─────────────────────────────────────────
    firstName: {
      type: String,
      required: [true, 'First name is required'],
      trim: true,
      maxlength: [50, 'First name cannot exceed 50 characters'],
    },

    lastName: {
      type: String,
      required: [true, 'Last name is required'],
      trim: true,
      maxlength: [50, 'Last name cannot exceed 50 characters'],
    },

    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
      lowercase: true,
      trim: true,
      match: [/^\S+@\S+\.\S+$/, 'Please provide a valid email address'],
    },

    // ── Credentials ───────────────────────────────────────
    password: {
      type: String,
      minlength: [8, 'Password must be at least 8 characters'],
      select: false, // Never returned in queries by default
    },

    // ── Role & Status ─────────────────────────────────────
    role: {
      type: String,
      enum: {
        values: ROLES,
        message: '{VALUE} is not a valid role',
      },
      default: 'employee',
    },

    isActive: {
      type: Boolean,
      default: true,
    },

    // ── Invite / Set-Password Flow ────────────────────────
    // Admin creates a user → system generates an invite token
    // User clicks the link, sets their password, token is cleared
    inviteToken: {
      type: String,
      select: false,
    },

    inviteTokenExpires: {
      type: Date,
      select: false,
    },

    hasSetPassword: {
      type: Boolean,
      default: false,
    },

    // ── Refresh Tokens (rotation) ─────────────────────────
    // Store hashed refresh tokens to support multi-device & revocation
    refreshTokens: {
      type: [
        {
          tokenHash: { type: String, required: true },
          createdAt: { type: Date, default: Date.now },
          expiresAt: { type: Date, required: true },
        },
      ],
      select: false,
      default: [],
    },

    // ── Security ──────────────────────────────────────────
    passwordChangedAt: {
      type: Date,
      select: false,
    },

    loginAttempts: {
      type: Number,
      default: 0,
      select: false,
    },

    lockUntil: {
      type: Date,
      select: false,
    },

    // ── Audit ─────────────────────────────────────────────
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },

    lastLoginAt: {
      type: Date,
    },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// ── Indexes ────────────────────────────────────────────────
userSchema.index({ email: 1 });
userSchema.index({ role: 1 });
userSchema.index({ inviteToken: 1 });

// ── Virtuals ───────────────────────────────────────────────
userSchema.virtual('fullName').get(function () {
  return `${this.firstName} ${this.lastName}`;
});

userSchema.virtual('isLocked').get(function () {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// ── Pre-save: Hash password ────────────────────────────────
userSchema.pre('save', async function (next) {
  if (!this.isModified('password') || !this.password) return next();
  const salt = await bcrypt.genSalt(12);
  this.password = await bcrypt.hash(this.password, salt);
  if (!this.isNew) this.passwordChangedAt = new Date();
  next();
});

// ── Instance method: Compare password ─────────────────────
userSchema.methods.comparePassword = async function (candidatePassword) {
  if (!this.password) return false;
  return bcrypt.compare(candidatePassword, this.password);
};

// ── Instance method: Increment login attempts (brute-force) ─
const MAX_LOGIN_ATTEMPTS = 5;
const LOCK_DURATION_MS = 30 * 60 * 1000; // 30 minutes

userSchema.methods.incrementLoginAttempts = async function () {
  // If previous lock has expired, reset
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $set: { loginAttempts: 1 },
      $unset: { lockUntil: 1 },
    });
  }

  const update = { $inc: { loginAttempts: 1 } };

  if (this.loginAttempts + 1 >= MAX_LOGIN_ATTEMPTS && !this.isLocked) {
    update.$set = { lockUntil: new Date(Date.now() + LOCK_DURATION_MS) };
  }

  return this.updateOne(update);
};

// ── Instance method: Reset login attempts on success ───────
userSchema.methods.resetLoginAttempts = async function () {
  return this.updateOne({
    $set: { loginAttempts: 0, lastLoginAt: new Date() },
    $unset: { lockUntil: 1 },
  });
};

const User = mongoose.model('User', userSchema);

export { ROLES };
export default User;