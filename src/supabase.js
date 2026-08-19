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
  const { data, error } = await supabase
    .from('users')
    .select('*')
    .eq('status', 'active')
    .order('created_at', { ascending: false });
  if (error) return [];
  return data;
}

// Get all leads
export async function getAllLeads() {
  const { data, error } = await supabase
    .from('leads')
    .select('*')
    .order('created_at', { ascending: false });
  if (error) return [];
  return data;
}

// Get sales dashboard stats
export async function getSalesStats() {
  const { data, error } = await supabase
    .from('sales_dashboard')
    .select('*')
    .single();
  if (error) return null;
  return data;
}

// Get marketing view
export async function getMarketingData() {
  const { data, error } = await supabase
    .from('marketing_view')
    .select('*')
    .order('joined', { ascending: false });
  if (error) return [];
  return data;
}

// Update lead status
export async function updateLeadStatus(leadId, status, notes) {
  const { error } = await supabase
    .from('leads')
    .update({ status, notes, updated_at: new Date().toISOString() })
    .eq('id', leadId);
  if (error) return { error: error.message };
  return { success: true };
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
  const expires = new Date();
  expires.setMonth(expires.getMonth() + 1);
  const { error } = await supabase
    .from('users')
    .update({ plan: 'pro', plan_expires_at: expires.toISOString(), updated_at: new Date().toISOString() })
    .eq('id', userId);
  if (error) return { error: error.message };
  await logAudit(userId, 'admin_pushed_to_pro', 'users', userId, {});
  return { success: true };
}

export async function cancelPro(userId) {
  const { error } = await supabase
    .from('users')
    .update({ plan: 'free', plan_expires_at: null, updated_at: new Date().toISOString() })
    .eq('id', userId);
  if (error) return { error: error.message };
  await logAudit(userId, 'admin_cancelled_pro', 'users', userId, {});
  return { success: true };
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
  const user = await getUser(email.toLowerCase().trim());
  if (!user) return { error: 'No account found with this email address. Please check the email or sign up.' };

  // If OAuth account, tell user to sign in with their provider
  if (user.auth_provider && user.auth_provider !== 'email') {
    const provider = user.auth_provider.charAt(0).toUpperCase() + user.auth_provider.slice(1);
    return { 
      error: `This email is linked to ${provider} sign-in. Please use the ${provider} button to sign in instead of a password reset.`,
      isOAuth: true,
      provider: user.auth_provider
    };
  }

  // Generate a 6-digit reset code
  const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

  // Save reset token to database
  const { error } = await supabase
    .from('password_resets')
    .insert([{
      user_id: user.id,
      token: resetCode,
      expires_at: expiresAt.toISOString(),
      used: false,
    }]);

  if (error) return { error: error.message };

  await logAudit(user.id, 'password_reset_requested', 'users', user.id, { email });

  // In production this would send an email via Supabase Edge Functions
  // For now we return the code so you can test it
  console.log(`[SCAN365 DEV] Password reset code for ${email}: ${resetCode}`);

  return { success: true, resetCode, userId: user.id };
}

// Step 2: Verify reset code
export async function verifyResetCode(email, code) {
  const user = await getUser(email);
  if (!user) return { error: 'No account found.' };

  const { data: reset, error } = await supabase
    .from('password_resets')
    .select('*')
    .eq('user_id', user.id)
    .eq('token', code)
    .eq('used', false)
    .gt('expires_at', new Date().toISOString())
    .order('created_at', { ascending: false })
    .limit(1)
    .single();

  if (error || !reset) return { error: 'Invalid or expired reset code. Please request a new one.' };

  return { success: true, userId: user.id, resetId: reset.id };
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

  // Mark token as used
  await supabase.from('password_resets').update({ used: true }).eq('id', resetId);

  await logAudit(userId, 'password_reset_completed', 'users', userId, {});
  return { success: true };
}
