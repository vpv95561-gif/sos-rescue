const portalYear = document.getElementById('year');
const portalHeader = document.querySelector('.site-header');
const portalMenuButton = document.querySelector('.menu-toggle');
const authPanel = document.getElementById('authPanel');
const dashboardPanel = document.getElementById('dashboardPanel');
const setupPanel = document.getElementById('setupPanel');
const authFormsPanel = document.getElementById('authFormsPanel');
const dashboardStatus = document.getElementById('dashboardStatus');
let csrfToken = '';
let currentUser = null;
let vendorDashboardData = null;

if (portalYear) portalYear.textContent = new Date().getFullYear();

if (portalMenuButton && portalHeader) {
  portalMenuButton.addEventListener('click', () => {
    const isOpen = portalHeader.classList.toggle('is-open');
    portalMenuButton.setAttribute('aria-expanded', String(isOpen));
  });
}

const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
}[character]));

const apiRequest = async (path, options = {}) => {
  const headers = new Headers(options.headers || {});
  if (options.body !== undefined) headers.set('Content-Type', 'application/json');
  if (options.csrf !== false && options.method && options.method !== 'GET' && csrfToken) {
    headers.set('X-CSRF-Token', csrfToken);
  }
  const response = await fetch(path, {
    credentials: 'same-origin',
    cache: 'no-store',
    ...options,
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body)
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(result.error || `Request failed (${response.status}).`);
  return result;
};

const showStatus = (element, message, isError = false) => {
  if (!element) return;
  element.textContent = message;
  element.classList.toggle('portal-status-error', isError);
  element.classList.toggle('portal-status-success', Boolean(message) && !isError);
};

const toggleAuthForm = (view) => {
  document.querySelectorAll('[data-auth-tab]').forEach((tab) => {
    const selected = tab.dataset.authTab === view;
    tab.classList.toggle('is-active', selected);
    tab.setAttribute('aria-selected', String(selected));
  });
  document.querySelectorAll('[data-auth-form]').forEach((form) => {
    form.hidden = form.dataset.authForm !== view;
  });
  const enroll = view === 'enroll';
  document.getElementById('authAsideTitle').textContent = enroll ? 'Work with a better local network.' : 'Welcome back.';
  document.getElementById('authAsideCopy').textContent = enroll
    ? 'Apply to receive roadside jobs and list your workshop after approval.'
    : 'Sign in to manage requests and workshop operations.';
};

document.querySelectorAll('[data-auth-tab]').forEach((tab) => {
  tab.addEventListener('click', () => toggleAuthForm(tab.dataset.authTab));
});

const setAuthenticatedView = async (user, csrf) => {
  currentUser = user;
  csrfToken = csrf || csrfToken;
  authPanel.hidden = true;
  dashboardPanel.hidden = false;
  document.getElementById('portalUserLabel').textContent = user.name;
  document.getElementById('portalUserLabel').hidden = false;
  document.getElementById('logoutButton').hidden = false;
  document.getElementById('dashboardRole').textContent = user.role === 'admin' ? 'ADMIN OPERATIONS' : 'SERVICE PARTNER';
  document.getElementById('dashboardHeading').textContent = user.role === 'admin' ? 'Admin dashboard' : 'Vendor workspace';
  document.getElementById('adminDashboard').hidden = user.role !== 'admin';
  document.getElementById('vendorDashboard').hidden = user.role !== 'vendor';
  await loadDashboard();
};

const renderAdmin = (data) => {
  const stats = [
    ['Open jobs', data.counts.openJobs],
    ['Online partners', data.counts.onlineVendors],
    ['Vendor reviews', data.counts.pendingVendors],
    ['Payment reviews', data.counts.pendingSubscriptions],
    ['Listed workshops', data.counts.activeWorkshops]
  ];
  document.getElementById('adminStats').innerHTML = stats.map(([label, value]) => `
    <article class="portal-stat"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></article>
  `).join('');

  document.getElementById('adminVendors').innerHTML = data.vendors.length ? data.vendors.map((vendor) => `
    <article class="portal-record">
      <div class="record-main"><span class="record-eyebrow">${escapeHtml(vendor.status)} · ${escapeHtml(vendor.effective_availability)} · ${escapeHtml(vendor.city)}</span><h4>${escapeHtml(vendor.business_name || vendor.name)}</h4><p>${escapeHtml(vendor.name)} · <a href="mailto:${escapeHtml(vendor.email)}">${escapeHtml(vendor.email)}</a> · <a href="tel:${escapeHtml(vendor.phone)}">${escapeHtml(vendor.phone)}</a></p><p>${escapeHtml(vendor.address || '')}</p><small>${escapeHtml(vendor.services || 'Services not specified')}</small></div>
      <div class="record-actions">${vendor.status === 'pending' ? `<button class="btn btn-primary" data-action="approve-vendor" data-id="${vendor.id}">Approve</button><button class="btn btn-secondary" data-action="reject-vendor" data-id="${vendor.id}">Reject</button>` : `<span class="subscription-badge ${vendor.status === 'approved' ? 'is-active' : ''}">${escapeHtml(vendor.status)}</span>${vendor.status === 'approved' ? `<button class="btn btn-secondary" data-action="set-vendor-availability" data-id="${vendor.id}" data-availability="${vendor.effective_availability === 'online' ? 'offline' : 'online'}" ${vendor.effective_availability !== 'online' && !vendor.has_active_subscription ? 'disabled' : ''}>Set ${vendor.effective_availability === 'online' ? 'offline' : 'online'}</button>` : ''}`}</div>
    </article>
  `).join('') : '<p class="portal-empty">No vendor accounts yet. New applications will appear here.</p>';

  document.getElementById('adminClients').innerHTML = data.clients.length ? data.clients.map((client) => `
    <article class="portal-record"><div class="record-main"><span class="record-eyebrow">${client.request_count} REQUEST${client.request_count === 1 ? '' : 'S'} · LAST ${new Date(client.last_request).toLocaleDateString()}</span><h4>${escapeHtml(client.customer_name)}</h4><p><a href="tel:${escapeHtml(client.customer_phone)}">${escapeHtml(client.customer_phone)}</a></p><small>${escapeHtml(client.services || 'No service details')}</small></div><div class="record-actions"><a class="btn btn-secondary" href="tel:${escapeHtml(client.customer_phone)}">Call client</a></div></article>
  `).join('') : '<p class="portal-empty">Client records will appear when customers submit service requests.</p>';

  document.getElementById('adminSubscriptions').innerHTML = data.subscriptions.length ? data.subscriptions.map((subscription) => `
    <article class="portal-record"><div class="record-main"><span class="record-eyebrow">${escapeHtml(subscription.status.replaceAll('_', ' '))} · ₹${(subscription.price_paise / 100).toLocaleString('en-IN')}</span><h4>${escapeHtml(subscription.business_name || subscription.vendor_name)} · ${escapeHtml(subscription.plan)}</h4><p>${escapeHtml(subscription.vendor_email)} · Requested ${new Date(subscription.created_at).toLocaleDateString()}</p><small>${subscription.ends_at ? `Active until ${new Date(subscription.ends_at).toLocaleDateString()}` : 'Offline payment must be confirmed before activating the 30-day listing.'}</small></div><div class="record-actions">${subscription.status === 'pending_payment' ? `<button class="btn btn-primary" data-action="activate-subscription" data-id="${subscription.id}">Confirm payment &amp; activate</button>` : `<span class="subscription-badge ${subscription.status === 'active' ? 'is-active' : ''}">${escapeHtml(subscription.status.replaceAll('_', ' '))}</span>`}</div></article>
  `).join('') : '<p class="portal-empty">No subscription records yet.</p>';

  document.getElementById('adminJobs').innerHTML = data.jobs.length ? data.jobs.map((job) => `
    <article class="portal-record"><div class="record-main"><span class="record-eyebrow">${escapeHtml(job.reference)} · ${escapeHtml(job.status.replaceAll('_', ' '))}</span><h4>${escapeHtml(job.issue)} · ${escapeHtml(job.vehicle)}</h4><p>${escapeHtml(job.customer_name)} · ${escapeHtml(job.customer_phone)} · ${escapeHtml(job.location)}</p><small>${new Date(job.created_at).toLocaleString()}${job.business_name ? ` · ${escapeHtml(job.business_name)}` : ''}</small></div><div class="record-actions">${['open', 'accepted'].includes(job.status) ? `<button class="btn btn-secondary" data-action="cancel-job" data-id="${job.id}">Cancel request</button>` : ''}</div></article>
  `).join('') : '<p class="portal-empty">No service requests yet. New customer bookings will appear here.</p>';
};

const subscriptionIsActive = (subscription) => subscription?.status === 'active' && subscription.ends_at && new Date(subscription.ends_at) > new Date();

const renderVendor = (data) => {
  vendorDashboardData = data;
  const { workshop, subscription, jobs, user } = data;
  const banner = document.getElementById('vendorStatusBanner');
  const approved = user.status === 'approved';
  const activeSubscription = subscriptionIsActive(subscription);
  const pendingPayment = subscription?.status === 'pending_payment';

  if (user.status === 'pending') {
    banner.innerHTML = '<strong>Application under review</strong><span>An administrator must approve your workshop before you can request listing activation or accept jobs.</span>';
  } else if (user.status === 'rejected') {
    banner.innerHTML = '<strong>Application not approved</strong><span>Contact the administrator if you believe this decision needs review.</span>';
  } else if (activeSubscription) {
    banner.innerHTML = `<strong>Approved partner · Listing active</strong><span>Your plan renews or expires on ${escapeHtml(new Date(subscription.ends_at).toLocaleDateString())}.</span>`;
  } else if (pendingPayment) {
    banner.innerHTML = '<strong>Payment confirmation pending</strong><span>Your workshop is approved. Listing and job acceptance unlock after the administrator confirms your subscription payment.</span>';
  } else {
    banner.innerHTML = '<strong>Workshop approved · Subscription required</strong><span>Choose a plan, complete the agreed offline payment, then wait for admin confirmation.</span>';
  }
  banner.className = `vendor-status-banner ${approved ? 'is-approved' : user.status === 'rejected' ? 'is-rejected' : 'is-pending'}`;

  const availabilityPanel = document.getElementById('vendorAvailabilityPanel');
  const availabilityLabel = document.getElementById('vendorAvailabilityLabel');
  const availabilityButton = document.getElementById('vendorAvailabilityButton');
  const availabilityHelp = document.getElementById('vendorAvailabilityHelp');
  const isOnline = user.availability === 'online';
  availabilityLabel.textContent = isOnline ? 'Online' : 'Offline';
  availabilityPanel.classList.toggle('is-online', isOnline);
  availabilityPanel.classList.toggle('is-offline', !isOnline);
  availabilityButton.textContent = isOnline ? 'Go offline' : 'Go online';
  availabilityButton.dataset.action = 'set-availability';
  availabilityButton.dataset.availability = isOnline ? 'offline' : 'online';
  availabilityButton.disabled = !isOnline && (!approved || !activeSubscription);
  availabilityHelp.textContent = isOnline
    ? 'You are visible to dispatch and can receive new requests. Go offline to pause.'
    : approved && activeSubscription
      ? 'You are not receiving new requests. Go online when your workshop is ready.'
      : 'Online mode requires admin approval and an active workshop subscription.';

  const profileForm = document.getElementById('workshopForm');
  if (workshop && profileForm) {
    for (const field of ['businessName', 'phone', 'city', 'address', 'services', 'description']) {
      if (profileForm.elements[field]) profileForm.elements[field].value = workshop[field === 'businessName' ? 'business_name' : field] || '';
    }
    profileForm.elements.listingEnabled.checked = Boolean(workshop.listing_enabled);
  }
  const profileEnabled = approved && activeSubscription;
  profileForm.querySelectorAll('input,textarea,button').forEach((control) => { control.disabled = !profileEnabled; });
  profileForm.querySelector('.portal-status').textContent = profileEnabled ? '' : 'Profile editing and public listing require an approved vendor and active subscription.';

  const subscriptionTitle = document.getElementById('subscriptionTitle');
  const subscriptionDescription = document.getElementById('subscriptionDescription');
  const subscriptionState = document.getElementById('subscriptionState');
  if (activeSubscription) {
    subscriptionTitle.textContent = `${subscription.plan} plan active`;
    subscriptionDescription.textContent = `Your current listing access ends ${new Date(subscription.ends_at).toLocaleDateString()}.`;
    subscriptionState.innerHTML = '<span class="subscription-badge is-active">Active</span>';
  } else if (pendingPayment) {
    subscriptionTitle.textContent = `${subscription.plan} · awaiting confirmation`;
    subscriptionDescription.textContent = 'An administrator will activate the plan after confirming the offline payment.';
    subscriptionState.innerHTML = '<span class="subscription-badge">Payment review</span>';
  } else {
    subscriptionTitle.textContent = approved ? 'Choose a listing plan' : 'Plan selection after approval';
    subscriptionDescription.textContent = approved ? 'Choose a plan and arrange payment with the administrator.' : 'Your application must be approved before you can request a plan.';
    subscriptionState.innerHTML = '';
  }
  document.querySelectorAll('.subscription-option').forEach((button) => {
    button.disabled = !approved || activeSubscription || pendingPayment;
  });
  const listing = document.getElementById('listingEligibility');
  listing.textContent = workshop?.listing_enabled && activeSubscription && approved
    ? 'Your workshop is visible in the public directory.'
    : 'Your workshop is not listed yet.';

  document.getElementById('vendorJobs').innerHTML = jobs.length ? jobs.map((job) => `
    <article class="portal-record"><div class="record-main"><span class="record-eyebrow">${escapeHtml(job.reference)} · ${escapeHtml(job.status.replaceAll('_', ' '))}</span><h4>${escapeHtml(job.issue)} · ${escapeHtml(job.vehicle)}</h4><p>${escapeHtml(job.location)}</p>${job.customer_name ? `<p>${escapeHtml(job.customer_name)} · <a href="tel:${escapeHtml(job.customer_phone)}">${escapeHtml(job.customer_phone)}</a></p>` : ''}<small>${new Date(job.created_at).toLocaleString()}</small></div><div class="record-actions">${job.status === 'open' ? `<button class="btn btn-primary" data-action="accept-job" data-id="${job.id}" ${!approved || !activeSubscription ? 'disabled' : ''}>${approved && activeSubscription ? 'Accept request' : 'Requires active plan'}</button>` : job.status === 'accepted' ? `<button class="btn btn-secondary" data-action="complete-job" data-id="${job.id}">Mark complete</button>` : ''}</div></article>
  `).join('') : `<p class="portal-empty">${isOnline ? 'No open requests are available right now.' : 'You are offline. Go online to receive new roadside requests.'}</p>`;
};

const loadDashboard = async () => {
  try {
    const endpoint = currentUser?.role === 'admin' ? '/api/admin/dashboard' : '/api/vendor/dashboard';
    const result = await apiRequest(endpoint);
    if (currentUser.role === 'admin') renderAdmin(result);
    else renderVendor(result);
    showStatus(dashboardStatus, '');
  } catch (error) {
    showStatus(dashboardStatus, error.message, true);
  }
};

const submitAuth = async (formElement, endpoint, statusMessage) => {
  const status = formElement.querySelector('.portal-status');
  const values = Object.fromEntries(new FormData(formElement));
  showStatus(status, 'Please wait…');
  try {
    const result = await apiRequest(endpoint, { method: 'POST', body: values, csrf: false });
    csrfToken = result.csrf;
    showStatus(status, statusMessage);
    await setAuthenticatedView(result.user, result.csrf);
  } catch (error) {
    showStatus(status, error.message, true);
  }
};

document.getElementById('setupForm').addEventListener('submit', (event) => {
  event.preventDefault();
  submitAuth(event.currentTarget, '/api/setup', 'Administrator account created.');
});

document.getElementById('loginForm').addEventListener('submit', (event) => {
  event.preventDefault();
  submitAuth(event.currentTarget, '/api/login', 'Signed in.');
});

document.getElementById('vendorEnrollForm').addEventListener('submit', (event) => {
  event.preventDefault();
  submitAuth(event.currentTarget, '/api/register/vendor', 'Application received.');
});

document.getElementById('logoutButton').addEventListener('click', async () => {
  try { await apiRequest('/api/logout', { method: 'POST', body: {} }); } catch {}
  currentUser = null;
  csrfToken = '';
  dashboardPanel.hidden = true;
  authPanel.hidden = false;
  document.getElementById('portalUserLabel').hidden = true;
  document.getElementById('logoutButton').hidden = true;
  await initializePortal();
});

document.getElementById('refreshDashboardButton').addEventListener('click', loadDashboard);

document.getElementById('adminDashboard').addEventListener('click', async (event) => {
  const button = event.target.closest('[data-action]');
  if (!button) return;
  const action = button.dataset.action;
  const messages = {
    'approve-vendor': 'Approve this vendor application?',
    'reject-vendor': 'Reject this vendor application?',
    'activate-subscription': 'Confirm payment was received offline and activate this 30-day subscription?',
    'cancel-job': 'Cancel this customer request?',
    'set-vendor-availability': `Set this partner ${button.dataset.availability}?`
  };
  if (!window.confirm(messages[action] || 'Continue with this action?')) return;
  button.disabled = true;
  try {
    let path;
    let body = {};
    if (action === 'approve-vendor' || action === 'reject-vendor') {
      path = `/api/admin/vendors/${button.dataset.id}/status`;
      body = { status: action === 'approve-vendor' ? 'approved' : 'rejected' };
    } else if (action === 'activate-subscription') {
      path = `/api/admin/subscriptions/${button.dataset.id}/activate`;
    } else if (action === 'set-vendor-availability') {
      path = `/api/admin/vendors/${button.dataset.id}/availability`;
      body = { availability: button.dataset.availability };
    } else {
      path = `/api/admin/jobs/${button.dataset.id}/cancel`;
    }
    await apiRequest(path, { method: 'POST', body });
    await loadDashboard();
    showStatus(dashboardStatus, 'Update saved.');
  } catch (error) {
    button.disabled = false;
    showStatus(dashboardStatus, error.message, true);
  }
});

document.getElementById('vendorDashboard').addEventListener('click', async (event) => {
  const button = event.target.closest('[data-action], [data-plan]');
  if (!button) return;
  if (button.dataset.action === 'accept-job' && !window.confirm('Accept this roadside request? The customer phone will become visible to your workshop.')) return;
  const requestedAvailability = button.dataset.availability;
  if (button.dataset.action === 'set-availability') button.disabled = true;
  button.disabled = true;
  try {
    if (button.dataset.plan) {
      const result = await apiRequest('/api/vendor/subscription', { method: 'POST', body: { plan: button.dataset.plan } });
      showStatus(document.getElementById('subscriptionStatus'), `Plan request #${result.subscriptionId} submitted. Arrange payment offline; the administrator must confirm it.`);
    } else if (button.dataset.action === 'accept-job') {
      await apiRequest(`/api/vendor/jobs/${button.dataset.id}/accept`, { method: 'POST', body: {} });
      showStatus(dashboardStatus, 'Request accepted. Customer contact details are now available.');
    } else if (button.dataset.action === 'complete-job') {
      await apiRequest(`/api/vendor/jobs/${button.dataset.id}/complete`, { method: 'POST', body: {} });
    } else if (button.dataset.action === 'set-availability') {
      await apiRequest('/api/vendor/availability', { method: 'POST', body: { availability: button.dataset.availability } });
    }
    await loadDashboard();
    if (button.dataset.plan) {
      showStatus(document.getElementById('subscriptionStatus'), 'Plan request submitted. Arrange the agreed offline payment; an administrator must confirm it.');
    } else if (button.dataset.action === 'accept-job') {
      showStatus(dashboardStatus, 'Request accepted. Customer contact details are now available.');
    } else if (button.dataset.action === 'complete-job') {
      showStatus(dashboardStatus, 'Request marked complete.');
    } else if (button.dataset.action === 'set-availability') {
      showStatus(document.getElementById('availabilityStatus'), `You are now ${requestedAvailability}.`);
    }
  } catch (error) {
    button.disabled = false;
    showStatus(button.dataset.plan ? document.getElementById('subscriptionStatus') : button.dataset.action === 'set-availability' ? document.getElementById('availabilityStatus') : dashboardStatus, error.message, true);
  }
});

document.getElementById('workshopForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const workshopForm = event.currentTarget;
  const status = workshopForm.querySelector('.portal-status');
  const values = Object.fromEntries(new FormData(workshopForm));
  values.listingEnabled = workshopForm.elements.listingEnabled.checked;
  try {
    await apiRequest('/api/vendor/workshop', { method: 'POST', body: values });
    showStatus(status, 'Workshop profile saved.');
    await loadDashboard();
  } catch (error) {
    showStatus(status, error.message, true);
  }
});

const initializePortal = async () => {
  authPanel.hidden = false;
  dashboardPanel.hidden = true;
  try {
    const [setup, session] = await Promise.all([
      apiRequest('/api/setup'),
      apiRequest('/api/me').catch(() => null)
    ]);
    setupPanel.hidden = !setup.needsSetup;
    authFormsPanel.hidden = false;
    if (session?.user) {
      await setAuthenticatedView(session.user, session.csrf);
    } else {
      toggleAuthForm('login');
    }
  } catch {
    setupPanel.hidden = true;
    authFormsPanel.hidden = false;
    showStatus(document.querySelector('#loginForm .portal-status'), 'The portal server is unavailable. Start the RoadRescue server to continue.', true);
  }
};

initializePortal();