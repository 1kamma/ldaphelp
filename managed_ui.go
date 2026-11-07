package main

const managedUIHTML = `
<style>
#management-modal { position:fixed; inset:0; z-index:9000; display:flex; align-items:center; justify-content:center; padding:10px; background:rgba(0,0,0,.7); }
#management-modal .modal-content { width:min(900px, 100%); }
.management-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(min(100%, 280px),1fr)); gap:16px; }
#management-modal label { display:block; margin:12px 0 5px; }
#management-modal input, #management-modal select { width:100%; min-width:0; box-sizing:border-box; padding:10px; background:var(--bg); color:var(--text); border:1px solid var(--border); border-radius:5px; font-size:16px; }
#management-modal .btn { margin:4px 4px 4px 0; min-height:44px; }
#management-status { white-space:pre-wrap; overflow-wrap:anywhere; margin:12px 0; }
</style>
<div id="management-modal" hidden role="dialog" aria-modal="true" aria-labelledby="management-title">
 <div class="modal-content modal-scroll-shell">
  <div class="modal-scroll-body">
   <h2 id="management-title" tabindex="-1">Servers &amp; Backups</h2>
   <p>Connections and destinations are private to your login. Saved LDAP and WebDAV passwords are encrypted in the database.</p>
   <div id="management-status" role="status" aria-live="polite"></div>
   <div class="management-grid">
    <section>
     <h3>Saved connections</h3>
     <div id="managed-resource-list"></div>
     <button class="btn" style="background:#2563eb" onclick="resetManagedForm()">New connection or destination</button>
     <h3>Generate backup</h3>
     <label for="backup-destination">Save to</label>
     <select id="backup-destination"></select>
     <p class="form-help">Exports the primary server and every attached server saved under your login: all readable naming-context entries (including users), OpenLDAP schema, and advertised subschemas. Any export error stops publication.</p>
     <p><strong>Sensitive, unencrypted archive:</strong> may include password hashes and personal data. Protect the destination. Online exports are not atomic snapshots; LDAP ACLs can hide entries and attributes.</p>
     <button id="run-backup" class="btn" style="background:#047857" onclick="runManagedBackup()">Back up all servers now</button>
    </section>
    <section>
     <h3 id="managed-form-title">New connection or destination</h3>
     <form id="managed-resource-form" onsubmit="saveManagedForm(event)">
      <input id="managed-id" type="hidden" value="0">
      <label for="managed-name">Name</label><input id="managed-name" required maxlength="256">
      <label for="managed-kind">Connection type</label>
      <select id="managed-kind" onchange="updateManagedFields()">
       <option value="ldap">LDAP server</option><option value="webdav">WebDAV over HTTPS</option>
       <option value="local">Local backup directory</option><option value="cifs">Mounted CIFS/SMB directory</option><option value="nfs">Mounted NFS directory</option>
      </select>
      <div id="managed-uri-field"><label for="managed-uri">Server URI</label><input id="managed-uri" type="url" autocapitalize="none" spellcheck="false"></div>
      <div id="managed-account-fields">
       <label for="managed-username" id="managed-username-label">Bind user DN</label><input id="managed-username" autocomplete="off" autocapitalize="none" spellcheck="false">
       <label for="managed-password">Password</label><input id="managed-password" type="password" autocomplete="new-password">
       <p class="form-help">Leave empty when editing to keep the saved password. Passwords are never returned to the browser.</p>
      </div>
      <div id="managed-path-field"><label for="managed-path" id="managed-path-label">Destination directory</label><input id="managed-path" autocapitalize="none" spellcheck="false"></div>
      <p id="managed-kind-help" class="form-help"></p>
      <button class="btn" style="background:#2563eb" type="submit">Save</button>
      <button class="btn" style="background:#4b5563" type="button" onclick="resetManagedForm()">Cancel editing</button>
     </form>
    </section>
   </div>
  </div>
  <div class="modal-actions modal-footer-fixed"><button class="btn" style="background:#4b5563" onclick="closeManagement()">Close</button></div>
 </div>
</div>
<script>
let managedResources = [];
let managementReturnFocus = null;
function managementStatus(message) { document.getElementById('management-status').textContent = message; }
async function managedRequest(url, method, body) {
    const options = {method:method || 'GET'};
    if (body !== undefined) { options.headers = {'Content-Type':'application/json'}; options.body = JSON.stringify(body); }
    const response = await fetch(url, options);
    if (!response.ok) throw new Error((await response.text()).trim() || 'Request failed');
    return response.json();
}
async function openManagement() {
    managementReturnFocus = document.activeElement;
    document.getElementById('management-modal').hidden = false;
    document.getElementById('management-title').focus();
    resetManagedForm();
    managementStatus('Loading saved connections...');
    try { await refreshManagedResources(); managementStatus(''); } catch (err) { managementStatus(err.message); }
}
function closeManagement() {
    document.getElementById('management-modal').hidden = true;
    document.getElementById('managed-password').value = '';
    if (managementReturnFocus) managementReturnFocus.focus();
}
function updateManagedFields() {
    const kind = document.getElementById('managed-kind').value;
    const ldap = kind === 'ldap', dav = kind === 'webdav';
    document.getElementById('managed-uri-field').hidden = !ldap && !dav;
    document.getElementById('managed-account-fields').hidden = !ldap && !dav;
    document.getElementById('managed-path-field').hidden = ldap;
    document.getElementById('managed-uri').required = ldap || dav;
    document.getElementById('managed-username').required = ldap;
    document.getElementById('managed-password').required = ldap && document.getElementById('managed-id').value === '0';
    document.getElementById('managed-path').required = !ldap && !dav;
    document.getElementById('managed-username-label').textContent = ldap ? 'Bind user DN' : 'WebDAV username (optional)';
    document.getElementById('managed-path-label').textContent = dav ? 'Existing subdirectory (relative, optional)' : 'Existing absolute directory on the application host';
    document.getElementById('managed-uri').placeholder = ldap ? 'ldaps://ldap.example.com:636' : 'https://storage.example.com/backups/';
    document.getElementById('managed-kind-help').textContent = ldap
        ? 'Use LDAPS on untrusted networks. Plain ldap:// does not encrypt credentials in transit. Schema editing supports OpenLDAP cn=schema,cn=config; the saved bind identity needs schema permissions.'
        : dav ? 'The collection and subdirectory must already exist. HTTPS certificate verification is enabled. The server must support PUT and MOVE; redirects are not followed.'
        : kind === 'local' ? 'The directory must already exist and be writable by LDAP Help. Files are created privately; the filesystem must support hard links for atomic publication.'
        : 'Mount the CIFS/NFS share on the application host first, using host-managed credentials or Kerberos. Enter the mounted backup subdirectory here. LDAP Help does not mount shares or store mount credentials. The mount must support hard links and be writable by LDAP Help.';
}
function resetManagedForm() {
    document.getElementById('managed-resource-form').reset();
    document.getElementById('managed-id').value = '0';
    document.getElementById('managed-form-title').textContent = 'New connection or destination';
    updateManagedFields();
}
function editManagedResource(item) {
    for (const field of ['id','name','kind','uri','username','path']) document.getElementById('managed-' + field).value = item[field];
    document.getElementById('managed-password').value = '';
    document.getElementById('managed-form-title').textContent = 'Edit ' + item.name;
    updateManagedFields();
    document.getElementById('managed-name').focus();
}
function managedButton(text, action, color) {
    const button = document.createElement('button'); button.type = 'button'; button.className = 'btn';
    button.style.background = color || '#2563eb'; button.textContent = text; button.onclick = action; return button;
}
async function refreshManagedResources() {
    managedResources = await managedRequest('/api/managed_resources');
    const list = document.getElementById('managed-resource-list'); list.replaceChildren();
    const destination = document.getElementById('backup-destination');
    const selected = destination.value; destination.replaceChildren();
    managedResources.forEach(item => {
        const card = document.createElement('div'); card.className = 'schema-card';
        const title = document.createElement('h4'); title.textContent = item.name;
        const description = document.createElement('p'); description.style.overflowWrap = 'anywhere';
        description.textContent = item.kind + ': ' + (item.uri || item.path) + (item.has_password ? ' (password saved)' : '');
        card.append(title, description, managedButton('Edit connection', () => editManagedResource(item), '#4b5563'));
        card.append(managedButton('Remove', async () => {
            if (!confirm('Remove ' + item.name + '? Existing backup files will not be deleted.')) return;
            try { await managedRequest('/api/managed_resources', 'DELETE', {id:item.id}); resetManagedForm(); await refreshManagedResources(); managementStatus('Connection removed.'); }
            catch (err) { managementStatus(err.message); }
        }, '#b91c1c'));
        if (item.kind === 'ldap') {
            card.append(managedButton('Object classes', () => loadAttachedSchema(item.id, 'olcObjectClasses')),
                managedButton('Attribute types', () => loadAttachedSchema(item.id, 'olcAttributeTypes')));
        } else {
            const option = document.createElement('option'); option.value = item.id; option.textContent = item.name + ' (' + item.kind + ')'; destination.append(option);
        }
        list.append(card);
    });
    if (!managedResources.length) list.textContent = 'No saved connections yet.';
    if ([...destination.options].some(option => option.value === selected)) destination.value = selected;
}
async function saveManagedForm(event) {
    event.preventDefault();
    const data = {};
    for (const field of ['name','kind','uri','username','path']) data[field] = document.getElementById('managed-' + field).value;
    data.id = Number(document.getElementById('managed-id').value);
    if (data.kind === 'ldap') data.path = '';
    if (!['ldap','webdav'].includes(data.kind)) { data.uri = ''; data.username = ''; }
    const password = document.getElementById('managed-password').value;
    if (password && ['ldap','webdav'].includes(data.kind)) data.password = password;
    try {
        await managedRequest('/api/managed_resources', 'POST', data);
        resetManagedForm(); await refreshManagedResources(); managementStatus('Connection saved.');
    } catch (err) { managementStatus(err.message); }
}
async function loadAttachedSchema(id, attr) {
    const item = managedResources.find(resource => resource.id === id);
    if (!item) { managementStatus('Connection not found; reopen Servers & Backups.'); return; }
    clearSchemaEditor();
    schemaViewState.mode = 'attached'; schemaViewState.attachedID = id; schemaViewState.replicaURL = item.name;
    schemaViewState.bindDN = ''; schemaViewState.bindPwd = ''; tempAdminDN = ''; tempAdminPwd = '';
    document.getElementById('schema-admin-dn').value = ''; document.getElementById('schema-admin-pwd').value = '';
    prepareSchemaTab(attr); document.getElementById('schema-operation').value = 'add';
    document.getElementById('schema-modal').style.display = 'flex';
    document.getElementById('schema-content').textContent = 'Loading attached server schema...';
    document.getElementById('schema-add-form').style.display = 'none';
    document.getElementById('schema-admin-login').style.display = 'none'; updateSchemaTargetNote();
    try {
        const data = await managedRequest('/api/attached_schema?id=' + encodeURIComponent(id));
        if (schemaViewState.mode !== 'attached' || schemaViewState.attachedID !== id || schemaViewState.currentAttr !== attr) return;
        renderSchemaManagerData(data, attr);
        const items = attr === 'olcAttributeTypes' ? (data.attributeTypes || []) : (data.objectClasses || []);
        document.querySelectorAll('#schema-fragment-root > .schema-card').forEach((card, index) => {
            card.append(managedButton('Use definition in editor', () => {
                document.getElementById('schema-dn').value = items[index].dn;
                document.getElementById('schema-value').value = items[index].raw;
                document.getElementById('schema-value').focus();
            }, '#4b5563'));
        });
    } catch (err) {
        if (schemaViewState.mode === 'attached' && schemaViewState.attachedID === id && schemaViewState.currentAttr === attr) document.getElementById('schema-content').textContent = err.message;
    }
}
async function runManagedBackup() {
    const id = Number(document.getElementById('backup-destination').value);
    if (!id) { managementStatus('Save and select a backup destination first.'); return; }
    if (!confirm('Export all readable entries and schemas from the primary server and every attached server? The resulting archive is not encrypted.')) return;
    const button = document.getElementById('run-backup'); button.disabled = true;
    managementStatus('Exporting all servers and uploading the archive. Keep this page open; large directories can take several minutes.');
    try {
        const result = await managedRequest('/api/backups', 'POST', {destination_id:id});
        managementStatus('Backup completed for ' + result.servers + ' server(s).\n' + result.location);
    } catch (err) { managementStatus('Backup failed: ' + err.message); }
    finally { button.disabled = false; }
}
document.getElementById('management-modal').addEventListener('keydown', event => {
    if (event.key === 'Escape' && document.getElementById('schema-modal').style.display !== 'flex') closeManagement();
    if (event.key === 'Tab' && document.getElementById('schema-modal').style.display !== 'flex') {
        const controls = [...event.currentTarget.querySelectorAll('button,input,select,[tabindex="0"]')].filter(node => !node.disabled && node.getClientRects().length);
        const first = controls[0], last = controls[controls.length - 1];
        if (event.shiftKey && (document.activeElement === first || document.activeElement.id === 'management-title')) { event.preventDefault(); last.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    }
});
</script>
`
