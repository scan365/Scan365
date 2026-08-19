// ================================================================
// SCAN365.IO - Supabase Configuration
// Project: scan365 | Region: Oceania (Sydney)
// IT Service Link | ABN 78 336 526 604
// ================================================================
import { createClient } from '@supabase/supabase-js';

const SUPABASE_URL = 'https://mxagzmnkhsrmqfmgsjny.supabase.co';
const SUPABASE_KEY = 'sb_publishable_F1qk8l7AixkWYwGAKh8w6g_haZk4n6c';

export const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// Backend API base (auth + payments run server-side with hashing/RLS-safe keys)
const API_BASE = 'https://scan-api-production-6f04.up.railway.app';


// ================================================================
// USER FUNCTIONS
// ================================================================

// Register new user
export async function registerUser(data) {
  try {
    const resp = await fetch(`${API_BASE}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    const result = await resp.json();
    if (!resp.ok) return { error: result.error || 'Registration failed.' };
    return { user: result.user };
  } catch (e) {
    return { error: 'Could not reach the server. Please try again.' };
  }
}

// Login user (via backend - bcrypt verification, auto-upgrades legacy passwords)
export async function loginUser(email, password) {
  try {
    const resp = await fetch(`${API_BASE}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    const result = await resp.json();
    if (!resp.ok) return { error: result.error || 'Login failed.' };
    return { user: result.user };
  } catch (e) {
    return { error: 'Could not reach the server. Please try again.' };
  }
}

// Get user by email (via backend)
export async function getUser(email) {
  try {
    const resp = await fetch(`${API_BASE}/api/data/get-user`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    const result = await resp.json();
    return result.user || null;
  } catch (e) {
    return null;
  }
}

// Update user profile (via backend)
export async function updateProfile(userId, profileData) {
  try {
    const resp = await fetch(`${API_BASE}/api/data/update-profile`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId, profileData }),
    });
    const result = await resp.json();
    if (!resp.ok) return { error: result.error || 'Update failed.' };
    return { success: true };
  } catch (e) {
    return { error: 'Could not reach the server. Please try again.' };
  }
}

// Update password (via backend - stored as bcrypt hash)
export async function updatePassword(userId, newPassword) {
  try {
    const resp = await fetch(`${API_BASE}/api/auth/change-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId, newPassword }),
    });
    const result = await resp.json();
    if (!resp.ok) return { error: result.error || 'Password change failed.' };
    return { success: true };
  } catch (e) {
    return { error: 'Could not reach the server. Please try again.' };
  }
}

// Toggle MFA (via backend)
export async function toggleMFA(userId, currentState) {
  try {
    const resp = await fetch(`${API_BASE}/api/data/toggle-mfa`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId, currentState }),
    });
    const result = await resp.json();
    if (!resp.ok) return { error: result.error || 'MFA toggle failed.' };
    return { success: true, mfaEnabled: result.mfaEnabled };
  } catch (e) {
    return { error: 'Could not reach the server. Please try again.' };
  }
}

// Upgrade to pro (via backend)
export async function upgradePlan(userId, plan, billingCycle, amount) {
  try {
    const resp = await fetch(`${API_BASE}/api/data/upgrade-plan`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId, plan, billingCycle, amount }),
    });
    const result = await resp.json();
    if (!resp.ok) return { error: result.error || 'Upgrade failed.' };
    return { success: true };
  } catch (e) {
    return { error: 'Could not reach the server. Please try again.' };
  }
}

// ================================================================
// SCAN FUNCTIONS
// ================================================================

// Save scan result
// Save scan result (via backend)
export async function saveScan(userId, scanData, isPro) {
  try {
    const resp = await fetch(`${API_BASE}/api/data/save-scan`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId, scanData, isPro }),
    });
    const result = await resp.json();
    if (!resp.ok) return { error: result.error || 'Could not save scan.' };
    return { scan: result.scan };
  } catch (e) {
    return { error: 'Could not reach the server. Please try again.' };
  }
}

// Get user scan history
export async function getScanHistory(userId, limit = 10) {
  try {
    const resp = await fetch(`${API_BASE}/api/data/scan-history`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId, limit }),
    });
    const result = await resp.json();
    return result.history || [];
  } catch (e) {
    return [];
  }
}

// ================================================================
// LEADS FUNCTIONS
// ================================================================

export async function saveLead(leadData) {
  try {
    const resp = await fetch(`${API_BASE}/api/data/save-lead`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ leadData }),
    });
    const result = await resp.json();
    if (!resp.ok) return { error: result.error || 'Could not save lead.' };
    return { success: true };
  } catch (e) {
    return { error: 'Could not reach the server. Please try again.' };
  }
}

// ================================================================
// ADMIN FUNCTIONS
// ================================================================

// Get all users for admin dashboard
export async function getAllUsers() {
  try {
    const resp = await fetch(`${API_BASE}/api/data/all-users`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    const result = await resp.json();
    return result.users || [];
  } catch (e) { return []; }
}

// Get all leads
export async function getAllLeads() {
  try {
    const resp = await fetch(`${API_BASE}/api/data/all-leads`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    const result = await resp.json();
    return result.leads || [];
  } catch (e) { return []; }
}

// Get sales dashboard stats
export async function getSalesStats() {
  try {
    const resp = await fetch(`${API_BASE}/api/data/sales-stats`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    const result = await resp.json();
    return result.stats || null;
  } catch (e) { return null; }
}

// Get marketing view
export async function getMarketingData() {
  try {
    const resp = await fetch(`${API_BASE}/api/data/marketing-data`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    const result = await resp.json();
    return result.data || [];
  } catch (e) { return []; }
}

// Update lead status
export async function updateLeadStatus(leadId, status, notes) {
  try {
    const resp = await fetch(`${API_BASE}/api/data/update-lead`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ leadId, status, notes }) });
    const result = await resp.json();
    if (!resp.ok) return { error: result.error || 'Update failed.' };
    return { success: true };
  } catch (e) { return { error: 'Could not reach the server. Please try again.' }; }
}

// Admin reset password (via backend - hashed)
export async function adminResetPassword(userId, newPassword) {
  try {
    const resp = await fetch(`${API_BASE}/api/auth/change-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId, newPassword }),
    });
    const result = await resp.json();
    if (!resp.ok) return { error: result.error || 'Reset failed.' };
    await logAudit(userId, 'admin_password_reset', 'users', userId, {});
    return { success: true };
  } catch (e) {
    return { error: 'Could not reach the server. Please try again.' };
  }
}

// Push user to pro
export async function pushToPro(userId) {
  try {
    const resp = await fetch(`${API_BASE}/api/data/push-to-pro`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ userId }) });
    const result = await resp.json();
    if (!resp.ok) return { error: result.error || 'Failed.' };
    return { success: true };
  } catch (e) { return { error: 'Could not reach the server. Please try again.' }; }
}

export async function cancelPro(userId) {
  try {
    const resp = await fetch(`${API_BASE}/api/data/cancel-pro`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ userId }) });
    const result = await resp.json();
    if (!resp.ok) return { error: result.error || 'Failed.' };
    return { success: true };
  } catch (e) { return { error: 'Could not reach the server. Please try again.' }; }
}

// ================================================================
// AUDIT LOG
// ================================================================
export async function logAudit(userId, action, entity, entityId, details) {
  try {
    await fetch(`${API_BASE}/api/data/log-audit`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId, action, entity, entityId, details }),
    });
  } catch (e) { /* non-fatal */ }
}

// ================================================================
// MONTHLY SCAN RESET CHECK
// ================================================================
export async function checkMonthlyReset(user) {
  try {
    const resp = await fetch(`${API_BASE}/api/data/check-monthly-reset`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user }),
    });
    const result = await resp.json();
    return result.user || user;
  } catch (e) {
    return user;
  }
}

// ================================================================
// FORGOT PASSWORD / RESET PASSWORD FUNCTIONS
// ================================================================

// Step 1: Request password reset - generates a token and saves it
export async function requestPasswordReset(email) {
  try {
    const resp = await fetch(`${API_BASE}/api/data/request-reset`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email }) });
    const result = await resp.json();
    if (!resp.ok) return { error: result.error || 'Reset request failed.', isOAuth: result.isOAuth, provider: result.provider };
    return { success: true, resetCode: result.resetCode, userId: result.userId };
  } catch (e) { return { error: 'Could not reach the server. Please try again.' }; }
}

// Step 2: Verify reset code
export async function verifyResetCode(email, code) {
  try {
    const resp = await fetch(`${API_BASE}/api/data/verify-reset`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, code }) });
    const result = await resp.json();
    if (!resp.ok) return { error: result.error || 'Invalid code.' };
    return { success: true, userId: result.userId, resetId: result.resetId };
  } catch (e) { return { error: 'Could not reach the server. Please try again.' }; }
}

// Step 3: Set new password after verification
export async function resetPasswordWithCode(email, code, newPassword) {
  const { success, userId, resetId, error } = await verifyResetCode(email, code);
  if (!success) return { error };

  if (newPassword.length < 8) return { error: 'Password must be at least 8 characters.' };

  // Update password via backend (stored as bcrypt hash)
  try {
    const resp = await fetch(`${API_BASE}/api/auth/change-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId, newPassword }),
    });
    const result = await resp.json();
    if (!resp.ok) return { error: result.error || 'Password reset failed.' };
  } catch (e) {
    return { error: 'Could not reach the server. Please try again.' };
  }

  // Mark token as used (via backend)
  try { await fetch(`${API_BASE}/api/data/mark-reset-used`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ resetId }) }); } catch (e) {}

  await logAudit(userId, 'password_reset_completed', 'users', userId, {});
  return { success: true };
}
