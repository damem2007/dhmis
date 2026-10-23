/* DHMIS appointment widget.  This file is deliberately framework-free so a
 * tenant can embed it in any CMS, static site, or server-rendered page. */
(function () {
  "use strict";

  var script = document.currentScript;
  if (!script) return;
  var organizationId = script.dataset.organizationId;
  if (!organizationId) throw new Error("DHMIS widget requires data-organization-id");
  var mode = script.dataset.mode || "button";
  var parentOrigin = script.dataset.parentOrigin || "";
  var apiBase = script.dataset.apiBase || new URL(script.src, document.baseURI).origin + "/v1/widgets/appointments";
  var target = script.dataset.target ? document.querySelector(script.dataset.target) : script.parentElement;
  if (!target) return;

  var state = { config: null, locations: [], providers: [], services: [], slots: [] };
  var root = target.attachShadow ? target.attachShadow({ mode: "open" }) : target;
  var style = document.createElement("style");
  root.appendChild(style);
  var mount = document.createElement("div");
  root.appendChild(mount);

  function escape(value) {
    return String(value == null ? "" : value).replace(/[&<>\"']/g, function (char) {
      return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char];
    });
  }
  function request(path, options) {
    var separator = path.indexOf("?") === -1 ? "?" : "&";
    if (parentOrigin) path += separator + "parent_origin=" + encodeURIComponent(parentOrigin);
    return fetch(apiBase + path, Object.assign({ headers: { "Content-Type": "application/json" } }, options || {})).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (body) {
        if (!response.ok) throw new Error(body.detail && (body.detail.message || body.detail) || "Booking widget request failed");
        return body;
      });
    });
  }
  function optionRows(items, placeholder) {
    return '<option value="">' + escape(placeholder) + '</option>' + items.map(function (item) {
      return '<option value="' + escape(item.id) + '">' + escape(item.name) + '</option>';
    }).join("");
  }
  function renderError(message) {
    mount.innerHTML = '<p class="error" role="alert">' + escape(message) + '</p>';
  }
  function renderForm() {
    var c = state.config;
    var locations = state.locations;
    var providers = state.providers;
    var services = state.services;
    mount.innerHTML = '<section class="widget" aria-label="' + escape(c.text.title) + '">' +
      '<h2>' + escape(c.text.title) + '</h2><p class="description">' + escape(c.text.description) + '</p>' +
      '<form id="dhmis-booking-form">' +
      '<div class="grid"><label>First name<input name="first_name" required autocomplete="given-name"></label><label>Last name<input name="last_name" required autocomplete="family-name"></label>' +
      '<label>Date of birth<input name="birth_date" type="date" required></label><label>Email<input name="email" type="email" required autocomplete="email"></label>' +
      '<label>Phone<input name="phone" autocomplete="tel"></label><label>Location<select name="location_id" required>' + optionRows(locations, "Choose a location") + '</select></label>' +
      '<label>Provider<select name="provider_id" required>' + optionRows(providers, "Choose a provider") + '</select></label><label>Service<select name="service_id" required>' + optionRows(services, "Choose a service") + '</select></label>' +
      '<label>Appointment date<input name="day" type="date" required></label><label>Available time<select name="slot" required><option value="">Choose a date first</option></select></label></div>' +
      '<button class="submit" type="submit">' + escape(c.text.button_label) + '</button><p class="status" aria-live="polite"></p></form></section>';
    var form = mount.querySelector("form");
    var location = form.elements.location_id;
    if (c.default_location_id) location.value = c.default_location_id;
    form.elements.day.addEventListener("change", loadSlots);
    form.elements.location_id.addEventListener("change", loadSlots);
    form.elements.provider_id.addEventListener("change", loadSlots);
    form.addEventListener("submit", submit);
  }
  function loadSlots() {
    var form = mount.querySelector("form");
    if (!form || !form.elements.day.value || !form.elements.location_id.value || !form.elements.provider_id.value) return;
    var select = form.elements.slot;
    select.innerHTML = '<option>Loading times…</option>';
    request("/availability?organization_id=" + encodeURIComponent(organizationId) + "&location_id=" + encodeURIComponent(form.elements.location_id.value) + "&provider_id=" + encodeURIComponent(form.elements.provider_id.value) + "&day=" + encodeURIComponent(form.elements.day.value)).then(function (slots) {
      state.slots = slots;
      select.innerHTML = slots.length ? '<option value="">Choose a time</option>' + slots.map(function (slot) { return '<option value="' + escape(slot.starts_at) + '">' + new Date(slot.starts_at).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" }) + '</option>'; }).join("") : '<option value="">No times available</option>';
    }).catch(function (error) { select.innerHTML = '<option value="">Unable to load times</option>'; form.querySelector(".status").textContent = error.message; });
  }
  function submit(event) {
    event.preventDefault();
    var form = event.currentTarget;
    var slot = state.slots.find(function (item) { return item.starts_at === form.elements.slot.value; });
    var service = state.services.find(function (item) { return item.id === form.elements.service_id.value; });
    var location = state.locations.find(function (item) { return item.id === form.elements.location_id.value; });
    if (!slot) return;
    var payload = { first_name: form.elements.first_name.value, last_name: form.elements.last_name.value, birth_date: form.elements.birth_date.value, email: form.elements.email.value, phone: form.elements.phone.value, location_id: form.elements.location_id.value, provider_id: form.elements.provider_id.value, chair: (location.chairs && location.chairs[0]) || "1", starts_at: slot.starts_at, ends_at: slot.ends_at, procedure: service ? service.name : "Appointment" };
    var status = form.querySelector(".status");
    status.textContent = "Submitting…";
    request("/appointments?organization_id=" + encodeURIComponent(organizationId), { method: "POST", body: JSON.stringify(payload) }).then(function () { form.innerHTML = '<p class="success">' + escape(state.config.text.success_message) + '</p>'; }).catch(function (error) { status.textContent = error.message; });
  }
  function open() { if (mode === "button") mount.innerHTML = ''; renderForm(); }
  function render() {
    var c = state.config;
    var d = c.design || { button_width: "auto", button_height: 48, button_radius: 8, button_font_size: 16, button_font_weight: "700", panel_width: 680, panel_radius: 14, panel_padding: 20 };
    style.textContent = ':host{font-family:' + c.font.family + ';color:' + c.branding["--widget-text"] + ';display:block}.widget{background:' + c.branding["--widget-surface"] + ';border:1px solid ' + c.branding["--widget-border"] + ';border-radius:' + d.panel_radius + 'px;padding:' + d.panel_padding + 'px;max-width:' + d.panel_width + 'px;box-sizing:border-box}.widget h2{margin:0 0 6px}.description{color:' + c.branding["--sage"] + ';margin-top:0}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.grid label{display:grid;gap:5px;font-size:13px;font-weight:600}.grid input,.grid select{font:inherit;border:1px solid ' + c.branding["--widget-border"] + ';border-radius:8px;padding:10px;background:' + c.branding["--widget-background"] + ';color:inherit}.submit{width:' + d.button_width + ';min-height:' + d.button_height + 'px;margin-top:16px;border:0;border-radius:' + d.button_radius + 'px;padding:0 20px;background:' + c.branding["--sage"] + ';color:#fff;font-family:' + c.font.family + ';font-size:' + d.button_font_size + 'px;font-weight:' + d.button_font_weight + ';cursor:pointer}.status,.error{color:#b42318}.success{color:' + c.branding["--sage"] + ';font-weight:700}@media(max-width:560px){.grid{grid-template-columns:1fr}}';
    if (c.font.url) { var link = document.createElement("link"); link.rel = "stylesheet"; link.href = c.font.url; document.head.appendChild(link); }
    if (mode === "button") { mount.innerHTML = '<button class="submit" type="button">' + escape(c.text.button_label) + '</button>'; mount.querySelector("button").addEventListener("click", open); }
    else if (mode === "iframe") {
      var frame = document.createElement("iframe");
      frame.title = c.text.title;
      frame.loading = "lazy";
      frame.style.cssText = "width:100%;min-height:560px;border:0;border-radius:14px;background:" + c.branding["--widget-surface"];
      frame.src = new URL("appointments-frame.html", script.src).href + "?organization_id=" + encodeURIComponent(organizationId) + "&parent_origin=" + encodeURIComponent(location.origin) + "&api=" + encodeURIComponent(apiBase) + "&widget=" + encodeURIComponent(new URL(script.src, document.baseURI).href);
      mount.appendChild(frame);
    } else open();
  }
  request("/config?organization_id=" + encodeURIComponent(organizationId)).then(function (config) { state.config = config; state.locations = config.locations || []; state.providers = config.providers || []; state.services = config.services || []; render(); }).catch(function (error) { renderError(error.message); });
}());
