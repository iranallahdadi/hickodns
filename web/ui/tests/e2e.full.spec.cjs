const { test, expect } = require('@playwright/test')
const path = require('path')

// Helper to log in programmatically via API
async function loginViaAPI(request, username, password) {
  const res = await request.post('http://localhost:8080/api/v1/auth/login', {
    data: { username, password }
  })
  if (!res.ok) throw new Error(`Login failed: ${res.status}`)
  const body = await res.json()
  return body.token
}

// Helper to set localStorage token
async function setTokenInPage(page, token) {
  await page.addInitScript(token => { 
    localStorage.setItem('token', token) 
  }, token)
}

test.describe('Admin login and auth flow', () => {
  test('login via UI form', async ({ page }) => {
    await page.goto('http://localhost:3000/')
    await page.click('text=Login')
    await page.fill('input[placeholder="username"]', 'admin')
    await page.fill('input[placeholder="password"]', 'admin123')
    await page.click('button:has-text("Login")')
    
    // Should redirect to admin
    await page.waitForURL('http://localhost:3000/admin*', { timeout: 10000 })
    expect(page.url()).toContain('/admin')
  })

  test('logout clears token', async ({ page, request }) => {
    const token = await loginViaAPI(request, 'admin', 'admin123')
    await setTokenInPage(page, token)
    
    await page.goto('http://localhost:3000/')
    await page.waitForSelector('text=Admin')
    
    await page.click('button:has-text("Logout")')
    await page.waitForURL('http://localhost:3000/login', { timeout: 5000 })
    
    // Token should be cleared
    const hasToken = await page.evaluate(() => localStorage.getItem('token'))
    expect(hasToken).toBeNull()
  })
})

test.describe('Admin Dashboard', () => {
  test('view dashboard with stats', async ({ page, request }) => {
    const token = await loginViaAPI(request, 'admin', 'admin123')
    await setTokenInPage(page, token)
    
    await page.goto('http://localhost:3000/admin')
    await page.waitForSelector('text=Admin Dashboard')
    
    // Should show stat cards
    await page.waitForSelector('text=Zones')
    await page.waitForSelector('text=Records')
    await page.waitForSelector('text=Active Servers')
  })
})

test.describe('Zones CRUD', () => {
  test('create zone via UI', async ({ page, request }) => {
    const token = await loginViaAPI(request, 'admin', 'admin123')
    await setTokenInPage(page, token)
    
    await page.goto('http://localhost:3000/admin/zones')
    await page.waitForSelector('input[placeholder="domain"]')
    
    const timestamp = Date.now()
    const domain = `test-${timestamp}.com`
    
    await page.fill('input[placeholder="domain"]', domain)
    await page.click('button:has-text("Create Zone")')
    
    // Should appear in table
    await page.waitForSelector(`text=${domain}`, { timeout: 10000 })
    expect(await page.locator(`text=${domain}`).count()).toBeGreaterThan(0)
  })

  test('view zone and manage records', async ({ page, request }) => {
    const token = await loginViaAPI(request, 'admin', 'admin123')
    await setTokenInPage(page, token)
    
    // Create a zone first
    const res = await request.post('http://localhost:8080/api/v1/zones', {
      headers: { 'Authorization': `Bearer ${token}` },
      data: { domain: `zone-${Date.now()}.com` }
    })
    const zoneData = await res.json()
    const zoneId = zoneData.id
    
    await page.goto('http://localhost:3000/admin/zones')
    await page.waitForSelector('a:has-text("Manage Records")')
    
    // Click manage records for the zone
    const manageLink = await page.locator('a:has-text("Manage Records")').first()
    await manageLink.click()
    
    // Should be on records page
    await page.waitForSelector('input[placeholder="value"]', { timeout: 10000 })
  })
})

test.describe('Records CRUD', () => {
  test('create A record', async ({ page, request }) => {
    const token = await loginViaAPI(request, 'admin', 'admin123')
    await setTokenInPage(page, token)
    
    // Create a zone first via API
    const zoneRes = await request.post('http://localhost:8080/api/v1/zones', {
      headers: { 'Authorization': `Bearer ${token}` },
      data: { domain: `records-test-${Date.now()}.com` }
    })
    const zoneData = await zoneRes.json()
    const zoneId = zoneData.id
    
    await page.goto(`http://localhost:3000/admin/zones/${zoneId}/records`)
    await page.waitForSelector('input[placeholder="name"]')
    
    await page.fill('input[placeholder="name"]', 'www')
    await page.selectOption('select', 'A')
    await page.fill('input[placeholder="value"]', '192.0.2.1')
    await page.fill('input[placeholder="ttl"]', '3600')
    
    await page.click('button:has-text("Create Record")')
    
    // Should appear in table
    await page.waitForSelector('text=www', { timeout: 10000 })
    await page.waitForSelector('text=192.0.2.1')
  })

  test('delete record', async ({ page, request }) => {
    const token = await loginViaAPI(request, 'admin', 'admin123')
    await setTokenInPage(page, token)
    
    // Create zone and record via API
    const zoneRes = await request.post('http://localhost:8080/api/v1/zones', {
      headers: { 'Authorization': `Bearer ${token}` },
      data: { domain: `delete-test-${Date.now()}.com` }
    })
    const zoneData = await zoneRes.json()
    const zoneId = zoneData.id
    
    const recRes = await request.post(`http://localhost:8080/api/v1/zones/${zoneId}/records`, {
      headers: { 'Authorization': `Bearer ${token}` },
      data: { name: 'test', record_type: 'A', value: '192.0.2.1', ttl: 3600 }
    })
    const recData = await recRes.json()
    
    await page.goto(`http://localhost:3000/admin/zones/${zoneId}/records`)
    await page.waitForSelector('text=test')
    
    // Click delete
    await page.click('button:has-text("Delete")')
    
    // Record should disappear
    await expect(page.locator('text=test')).not.toBeVisible({ timeout: 5000 })
  })
})

test.describe('Servers CRUD', () => {
  test('create and list servers', async ({ page, request }) => {
    const token = await loginViaAPI(request, 'admin', 'admin123')
    await setTokenInPage(page, token)
    
    await page.goto('http://localhost:3000/admin/servers')
    await page.waitForSelector('input[placeholder="name"]')
    
    const serverName = `server-${Date.now()}`
    await page.fill('input[placeholder="name"]', serverName)
    await page.fill('input[placeholder="address"]', '192.0.2.10')
    await page.fill('input[placeholder="region (optional)"]', 'us-east-1')
    
    await page.click('button:has-text("Create Server")')
    
    // Should appear in table
    await page.waitForSelector(`text=${serverName}`, { timeout: 10000 })
  })
})

test.describe('Users Admin CRUD', () => {
  test('create user via modal', async ({ page, request }) => {
    const token = await loginViaAPI(request, 'admin', 'admin123')
    await setTokenInPage(page, token)
    
    await page.goto('http://localhost:3000/admin/users')
    await page.waitForSelector('button:has-text("New")')
    
    await page.click('button:has-text("New")')
    await page.waitForSelector('input[placeholder="username"]')
    
    const username = `user-${Date.now()}`
    await page.fill('input[placeholder="username"]', username)
    await page.fill('input[placeholder="email"]', `${username}@example.com`)
    await page.selectOption('select', 'admin')
    
    await page.click('button:has-text("Save")')
    
    // Should appear in table
    await page.waitForSelector(`text=${username}`, { timeout: 10000 })
  })
})

test.describe('GeoRules', () => {
  test('view and create georule', async ({ page, request }) => {
    const token = await loginViaAPI(request, 'admin', 'admin123')
    await setTokenInPage(page, token)
    
    // Create a zone first
    const zoneRes = await request.post('http://localhost:8080/api/v1/zones', {
      headers: { 'Authorization': `Bearer ${token}` },
      data: { domain: `geo-${Date.now()}.com` }
    })
    const zoneData = await zoneRes.json()
    
    await page.goto('http://localhost:3000/admin/georules')
    await page.waitForSelector('select')
    
    // Zone select should load zones
    const options = await page.locator('select').first().locator('option').count()
    expect(options).toBeGreaterThan(1) // at least "Select a zone" + created zone
  })
})

test.describe('Audit Logs', () => {
  test('view audit logs page', async ({ page, request }) => {
    const token = await loginViaAPI(request, 'admin', 'admin123')
    await setTokenInPage(page, token)
    
    await page.goto('http://localhost:3000/admin/audit')
    await page.waitForSelector('text=Audit Logs')
    
    // Should have filter and export button
    await page.waitForSelector('input[placeholder="Filter logs..."]')
    await page.waitForSelector('button:has-text("Export CSV")')
  })
})

test.describe('Dark Mode', () => {
  test('toggle dark mode', async ({ page, request }) => {
    const token = await loginViaAPI(request, 'admin', 'admin123')
    await setTokenInPage(page, token)
    
    await page.goto('http://localhost:3000/admin')
    await page.waitForSelector('button:has-text("Dark")')
    
    // Toggle to dark
    await page.click('button:has-text("Dark")')
    
    // Check class is set
    const hasDark = await page.evaluate(() => 
      document.documentElement.classList.contains('dark')
    )
    expect(hasDark).toBe(true)
    
    // Should persist on reload
    await page.reload()
    const stillDark = await page.evaluate(() => 
      document.documentElement.classList.contains('dark')
    )
    expect(stillDark).toBe(true)
  })
})

test.describe('Bulk Import', () => {
  test('bulk import zones via CSV', async ({ page, request }) => {
    const token = await loginViaAPI(request, 'admin', 'admin123')
    await setTokenInPage(page, token)
    
    await page.goto('http://localhost:3000/admin/zones')
    await page.waitForSelector('input[type="file"]')
    
    // Create sample CSV
    const csvPath = path.join(__dirname, 'fixtures', 'zones.csv')
    await page.locator('input[type="file"]').setInputFiles(csvPath)
    
    // Click import
    await page.click('button:has-text("Import")')
    
    // Should show success (wait for a bulk entry to appear)
    await page.waitForSelector('text=example-bulk', { timeout: 10000 })
  })
})
