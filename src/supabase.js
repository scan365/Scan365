// ================================================================
// SCAN365.IO - Supabase Configuration
// Project: scan365 | Region: Oceania (Sydney)
// IT Service Link | ABN 78 336 526 604
// ================================================================
import { createClient } from '@supabase/supabase-js';

const SUPABASE_URL = 'https://mxagzmnkhsrmqfmgsjny.supabase.co';
const SUPABASE_KEY = 'sb_publishable_F1qk8l7AixkWYwGAKh8w6g_haZk4n6c';

export const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// ================================================================
// USER FUNCTIONS
// ================================================================

// Register new user
export async function registerUser(data) {
  const { data: existing } = await supabase
    .from('users')
    .select('id')
    .eq('email', data.email)
    .single();
  if (existing) return { error: 'Email already registered.' };

  const { data: user, error } = await supabase
    .from('users')
    .insert([{
      name: data.name,
      email: data.email,
      password_hash: data.password,
      company: data.company || '',
      auth_provider: data.authProvider || 'email',
      profile_complete: false,
      plan: 'free',
    }])
    .select()
    .single();

  if (error) return { error: error.message };

  await logAudit(user.id, 'user_registered', 'users', user.id, { provider: data.authProvider });
  return { user };
}

// Login user
export async function loginUser(email, password) {
  const { data: user, error } = await supabase
    .from('users')
    .select('*')
    .eq('email', email.toLowerCase())
    .eq('status', 'active')
    .single();

  if (error || !user) return { error: 'No account found with this email.' };
  if (user.password_hash !== password) return { error: 'Incorrect password.' };

  await supabase.from('users').update({ last_login: new Date().toISOString() }).eq('id', user.id);
  await logAudit(user.id, 'user_login', 'users', user.id, {});
  return { user };
}

// Get user by email
export async function getUser(email) {
  const { data, error } = await supabase
    .from('users')
    .select('*')
    .eq('email', email.toLowerCase())
    .single();
  if (error) return null;
  return data;
}

// Update user profile
export async function updateProfile(userId, profileData) {
  const { error } = await supabase
    .from('users')
    .update({ ...profileData, profile_complete: true, updated_at: new Date().toISOString() })
    .eq('id', userId);
  if (error) return { error: error.message };
  await logAudit(userId, 'profile_updated', 'users', userId, {});
  return { success: true };
}

// Update password
export async function updatePassword(userId, newPassword) {
  const { error } = await supabase
    .from('users')
    .update({ password_hash: newPassword, updated_at: new Date().toISOString() })
    .eq('id', userId);
  if (error) return { error: error.message };
  await logAudit(userId, 'password_changed', 'users', userId, {});
  return { success: true };
}

// Toggle MFA
export async function toggleMFA(userId, currentState) {
  const { error } = await supabase
    .from('users')
    .update({ mfa_enabled: !currentState, updated_at: new Date().toISOString() })
    .eq('id', userId);
  if (error) return { error: error.message };
  await logAudit(userId, currentState ? 'mfa_disabled' : 'mfa_enabled', 'users', userId, {});
  return { success: true, mfaEnabled: !currentState };
}

// Upgrade to pro
export async function upgradePlan(userId, plan, billingCycle, amount) {
  const expires = new Date();
  if (billingCycle === 'monthly') expires.setMonth(expires.getMonth() + 1);
  else if (billingCycle === 'quarterly') expires.setMonth(expires.getMonth() + 3);
  else expires.setFullYear(expires.getFullYear() + 1);

  const { error } = await supabase
    .from('users')
    .update({ plan, plan_expires_at: expires.toISOString(), updated_at: new Date().toISOString() })
    .eq('id', userId);
  if (error) return { error: error.message };

  await supabase.from('subscriptions').insert([{
    user_id: userId, plan, billing_cycle: billingCycle,
    amount_aud: amount, status: 'active', expires_at: expires.toISOString(),
  }]);

  await logAudit(userId, 'plan_upgraded', 'subscriptions', userId, { plan, billingCycle });
  return { success: true };
}

// ================================================================
// SCAN FUNCTIONS
// ================================================================

// Save scan result
export async function saveScan(userId, scanData, isPro) {
  const allFindings = Object.values(scanData.modules).flatMap(m => m.findings);
  const criticalCount = allFindings.filter(f => f.sev === 'critical').length;
  const highCount = allFindings.filter(f => f.sev === 'high').length;
  const mediumCount = allFindings.filter(f => f.sev === 'medium').length;
  const lowCount = allFindings.filter(f => f.sev === 'low').length;

  const { data: scan, error } = await supabase
    .from('scans')
    .insert([{
      user_id: userId,
      domain: scanData.domain,
      m365_domain: scanData.m365domain || null,
      overall_score: scanData.overallScore,
      risk_level: scanData.overallScore >= 70 ? 'Low Risk' : scanData.overallScore >= 45 ? 'Medium Risk' : 'High Risk',
      website_score: scanData.modules.website?.score,
      m365_score: scanData.modules.m365?.score,
      essential8_score: scanData.modules.essential8?.score,
      phishing_score: scanData.modules.phishing?.score,
      critical_count: criticalCount,
      high_count: highCount,
      medium_count: mediumCount,
      low_count: lowCount,
      scan_data: scanData,
      plan_at_scan: isPro ? 'pro' : 'free',
    }])
    .select()
    .single();

  if (error) return { error: error.message };

  // Save individual findings
  const findings = [];
  Object.entries(scanData.modules).forEach(([module, data]) => {
    data.findings.forEach(f => {
      findings.push({ scan_id: scan.id, module, severity: f.sev, title: f.title, detail: f.detail });
    });
  });
  if (findings.length > 0) {
    await supabase.from('scan_findings').insert(findings);
  }

  // Increment user scan count
  await supabase.rpc('increment_scan_count', { user_id_param: userId });

  await logAudit(userId, 'scan_completed', 'scans', scan.id, { domain: scanData.domain, score: scanData.overallScore });
  return { scan };
}

// Get user scan history
export async function getScanHistory(userId, limit = 10) {
  const { data, error } = await supabase
    .from('scans')
    .select('id, domain, overall_score, risk_level, scanned_at')
    .eq('user_id', userId)
    .order('scanned_at', { ascending: false })
    .limit(limit);
  if (error) return [];
  return data;
}

// ================================================================
// LEADS FUNCTIONS
// ================================================================

export async function saveLead(leadData) {
  const { error } = await supabase
    .from('leads')
    .insert([{
      name: leadData.name,
      email: leadData.email,
      phone: leadData.phone || null,
      interest: leadData.interest,
      source: leadData.source || 'chatbot',
      status: 'new',
    }]);
  if (error) return { error: error.message };
  return { success: true };
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

// Admin reset password
export async function adminResetPassword(userId, newPassword) {
  const { error } = await supabase
    .from('users')
    .update({ password_hash: newPassword, updated_at: new Date().toISOString() })
    .eq('id', userId);
  if (error) return { error: error.message };
  await logAudit(userId, 'admin_password_reset', 'users', userId, {});
  return { success: true };
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

// ================================================================
// AUDIT LOG
// ================================================================
export async function logAudit(userId, action, entity, entityId, details) {
  await supabase.from('audit_log').insert([{
    user_id: userId || null,
    action,
    entity,
    entity_id: entityId || null,
    details,
    created_at: new Date().toISOString(),
  }]);
}

// ================================================================
// MONTHLY SCAN RESET CHECK
// ================================================================
export async function checkMonthlyReset(user) {
  const resetDate = new Date(user.monthly_reset_at);
  const now = new Date();
  if (now.getMonth() !== resetDate.getMonth() || now.getFullYear() !== resetDate.getFullYear()) {
    await supabase
      .from('users')
      .update({ monthly_scans: 0, monthly_reset_at: now.toISOString().slice(0, 10) })
      .eq('id', user.id);
    return { ...user, monthly_scans: 0 };
  }
  return user;
}

// ================================================================
// FORGOT PASSWORD / RESET PASSWORD FUNCTIONS
// ================================================================

// Step 1: Request password reset - generates a token and saves it
export async function requestPasswordReset(email) {
  const user = await getUser(email);
  if (!user) return { error: 'No account found with this email address.' };

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

  // Update password
  const { error: updateError } = await supabase
    .from('users')
    .update({ password_hash: newPassword, updated_at: new Date().toISOString() })
    .eq('id', userId);

  if (updateError) return { error: updateError.message };

  // Mark token as used
  await supabase.from('password_resets').update({ used: true }).eq('id', resetId);

  await logAudit(userId, 'password_reset_completed', 'users', userId, {});
  return { success: true };
}
