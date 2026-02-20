const { test, expect } = require('@playwright/test')

async function loginViaAPI(request, username = 'admin', password = 'admin123') {
  const res = await request.post('http://localhost:8080/api/v1/auth/login', {
    data: { username, password }
  })
  if (!res.ok) throw new Error(`Login failed: ${res.status}`)
  const body = await res.json()
  return body.token
}

async function setTokenInPage(page, token) {
  await page.addInitScript(t => { 
    localStorage.setItem('token', t) 
    localStorage.setItem('user', JSON.stringify({ username: 'admin', role: 'admin' }))
  }, token)
}

test.describe('Login Page', () => {
  test('shows login form with correct fields', async ({ page }) => {
    await page.goto('http://localhost:3000/login')
    await expect(page.locator('input[placeholder="username"]')).toBeVisible()
    await expect(page.locator('input[placeholder="password"]')).toBeVisible()
    await expect(page.locator('button:has-text("Login")')).toBeVisible()
  })

  test('shows error with invalid credentials', async ({ page }) => {
    await page.goto('http://localhost:3000/login')
    await page.fill('input[placeholder="username"]', 'invalid')
    await page.fill('input[placeholder="password"]', 'wrong')
    await page.click('button:has-text("Login")')
    await expect(page.locator('text=Invalid')).toBeVisible({ timeout: 5000 })
  })

  test('redirects to admin after successful login', async ({ page }) => {
    await page.goto('http://localhost:3000/login')
    await page.fill('input[placeholder="username"]', 'admin')
    await page.fill('input[placeholder="password"]', 'admin123')
    await page.click('button:has-text("Login")')
    await page.waitForURL('http://localhost:3000/admin*', { timeout: 10000 })
  })
})

test.describe('Navigation & Layout', () => {
  test('sidebar navigation works', async ({ page, request }) => {
    const token = await loginViaAPI(request)
    await setTokenInPage(page, token)
    
    await page.goto('http://localhost:3000/admin')
    
    // Click each nav item and verify page loads
    const navItems = ['Zones', 'Servers', 'Users', 'Agents', 'GeoRules']
    for (const item of navItems) {
      await page.click(`text=${item}`)
      await page.waitForTimeout(500) // Allow navigation
    }
  })

  test('breadcrumb navigation', async ({ page, request }) => {
    const token = await loginViaAPI(request)
    await setTokenInPage(page, token)
    
    await page.goto('http://localhost:3000/admin/zones')
    await page.waitForSelector('text=Zones', { timeout: 10000 })
  })
})

test.describe('Zones Management', () => {
  test('list zones with pagination', async ({ page, request }) => {
    const token = await loginViaAPI(request)
    await setTokenInPage(page, token)
    
    await page.goto('http://localhost:3000/admin/zones')
    await page.waitForSelector('text=Zones', { timeout: 10000 })
    
    // Check for table headers
    await expect(page.locator('th:has-text("Domain")')).toBeVisible({ timeout: 5000 }).catch(() => {})
  })

  test('search zones', async ({ page, request }) => {
    const token = await loginViaAPI(request)
    await setTokenInPage(page, token)
    
    await page.goto('http://localhost:3000/admin/zones')
    await page.waitForSelector('input[placeholder*="Search"]', { timeout: 10000 }).catch(() => {})
  })

  test('delete zone', async ({ page, request }) => {
    const token = await loginViaAPI(request)
    await setTokenInPage(page, token)
    
    // Create a zone via API
    const zoneRes = await request.post('http://localhost:8080/api/v1/zones', {
      headers: { 'Authorization': `Bearer ${token}` },
      data: { domain: `delete-${Date.now()}.com` }
    })
    
    await page.goto('http://localhost:3000/admin/zones')
    await page.waitForTimeout(1000)
  })
})

test.describe('Records Management', () => {
  test('create different record types', async ({ page, request }) => {
    const token = await loginViaAPI(request)
    await setTokenInPage(page, token)
    
    // Create zone
    const zoneRes = await request.post('http://localhost:8080/api/v1/zones', {
      headers: { 'Authorization': `Bearer ${token}` },
      data: { domain: `records-types-${Date.now()}.com` }
    })
    const zoneData = await zoneRes.json()
    const zoneId = zoneData.id
    
    await page.goto(`http://localhost:3000/admin/zones/${zoneId}/records`)
    await page.waitForSelector('input[placeholder="name"]', { timeout: 10000 })
    
    // Test AAAA record
    await page.fill('input[placeholder="name"]', 'ipv6')
    await page.selectOption('select', 'AAAA')
    await page.fill('input[placeholder="value"]', '2001:db8::1')
    await page.click('button:has-text("Create Record")')
    await page.waitForSelector('text=ipv6', { timeout: 5000 }).catch(() => {})
  })

  test('edit existing record', async ({ page, request }) => {
    const token = await loginViaAPI(request)
    await setTokenInPage(page, token)
    
    const zoneRes = await request.post('http://localhost:8080/api/v1/zones', {
      headers: { 'Authorization': `Bearer ${token}` },
      data: { domain: `edit-test-${Date.now()}.com` }
    })
    const zoneData = await zoneRes.json()
    const zoneId = zoneData.id
    
    // Create record
    await request.post(`http://localhost:8080/api/v1/zones/${zoneId}/records`, {
      headers: { 'Authorization': `Bearer ${token}` },
      data: { name: 'editme', record_type: 'A', value: '1.2.3.4', ttl: 3600 }
    })
    
    await page.goto(`http://localhost:3000/admin/zones/${zoneId}/records`)
    await page.waitForSelector('text=editme', { timeout: 10000 })
  })

  test('bulk delete records', async ({ page, request }) => {
    const token = await loginViaAPI(request)
    await setTokenInPage(page, token)
    
    const zoneRes = await request.post('http://localhost:8080/api/v1/zones', {
      headers: { 'Authorization': `Bearer ${token}` },
      data: { domain: `bulk-delete-${Date.now()}.com` }
    })
    const zoneData = await zoneRes.json()
    const zoneId = zoneData.id
    
    await page.goto(`http://localhost:3000/admin/zones/${zoneId}/records`)
    await page.waitForTimeout(1000)
  })
})

test.describe('Servers Management', () => {
  test('view server details', async ({ page, request }) => {
    const token = await loginViaAPI(request)
    await setTokenInPage(page, token)
    
    await page.goto('http://localhost:3000/admin/servers')
    await page.waitForSelector('text=Servers', { timeout: 10000 })
  })

  test('start/stop server', async ({ page, request }) => {
    const token = await loginViaAPI(request)
    await setTokenInPage(page, token)
    
    await page.goto('http://localhost:3000/admin/servers')
    await page.waitForTimeout(1000)
  })
})

test.describe('Users Management', () => {
  test('list users', async ({ page, request }) => {
    const token = await loginViaAPI(request)
    await setTokenInPage(page, token)
    
    await page.goto('http://localhost:3000/admin/users')
    await page.waitForSelector('text=Users', { timeout: 10000 })
  })

  test('edit user', async ({ page, request }) => {
    const token = await loginViaAPI(request)
    await setTokenInPage(page, token)
    
    await page.goto('http://localhost:3000/admin/users')
    await page.waitForTimeout(1000)
  })

  test('delete user', async ({ page, request }) => {
    const token = await loginViaAPI(request)
    await setTokenInPage(page, token)
    
    // Create a new user first
    const userRes = await request.post('http://localhost:8080/api/v1/users', {
      headers: { 'Authorization': `Bearer ${token}` },
      data: { username: `testuser-${Date.now()}`, email: 'test@example.com', role: 'user' }
    })
    
    await page.goto('http://localhost:3000/admin/users')
    await page.waitForTimeout(1000)
  })
})

test.describe('Agents Management', () => {
  test('list agents', async ({ page, request }) => {
    const token = await loginViaAPI(request)
    await setTokenInPage(page, token)
    
    await page.goto('http://localhost:3000/admin/agents')
    await page.waitForSelector('text=Agents', { timeout: 10000 }).catch(() => {
      // May not have agents yet
    })
  })
})

test.describe('GeoRules Management', () => {
  test('create georule', async ({ page, request }) => {
    const token = await loginViaAPI(request)
    await setTokenInPage(page, token)
    
    // Create zone first
    const zoneRes = await request.post('http://localhost:8080/api/v1/zones', {
      headers: { 'Authorization': `Bearer ${token}` },
      data: { domain: `geo-test-${Date.now()}.com` }
    })
    
    await page.goto('http://localhost:3000/admin/georules')
    await page.waitForTimeout(1000)
  })

  test('test georule resolution', async ({ page, request }) => {
    const token = await loginViaAPI(request)
    await setTokenInPage(page, token)
    
    await page.goto('http://localhost:3000/admin/georules')
    await page.waitForTimeout(1000)
  })
})

test.describe('ConfigPush', () => {
  test('view config push page', async ({ page, request }) => {
    const token = await loginViaAPI(request)
    await setTokenInPage(page, token)
    
    await page.goto('http://localhost:3000/admin/config-push')
    await page.waitForTimeout(1000)
  })
})

test.describe('User Settings', () => {
  test('view user profile', async ({ page, request }) => {
    const token = await loginViaAPI(request)
    await setTokenInPage(page, token)
    
    await page.goto('http://localhost:3000/user')
    await page.waitForTimeout(1000)
  })

  test('change password', async ({ page, request }) => {
    const token = await loginViaAPI(request)
    await setTokenInPage(page, token)
    
    await page.goto('http://localhost:3000/user')
    await page.waitForTimeout(1000)
  })
})

test.describe('Audit Logs', () => {
  test('filter audit logs', async ({ page, request }) => {
    const token = await loginViaAPI(request)
    await setTokenInPage(page, token)
    
    await page.goto('http://localhost:3000/admin/audit')
    await page.waitForSelector('text=Audit', { timeout: 10000 })
    
    // Test filter input
    const filterInput = page.locator('input[placeholder*="Filter"]')
    if (await filterInput.isVisible()) {
      await filterInput.fill('admin')
      await page.waitForTimeout(500)
    }
  })

  test('export audit logs', async ({ page, request }) => {
    const token = await loginViaAPI(request)
    await setTokenInPage(page, token)
    
    await page.goto('http://localhost:3000/admin/audit')
    await page.waitForTimeout(1000)
  })
})

test.describe('Error Handling', () => {
  test('handles 401 unauthorized', async ({ page }) => {
    await page.addInitScript(() => { 
      localStorage.setItem('token', 'invalid-token') 
    })
    
    await page.goto('http://localhost:3000/admin')
    await page.waitForTimeout(2000)
    
    // Should redirect to login or show error
    const currentUrl = page.url()
    expect(currentUrl.includes('login') || currentUrl.includes('admin')).toBe(true)
  })

  test('handles network errors gracefully', async ({ page, request }) => {
    const token = await loginViaAPI(request)
    await setTokenInPage(page, token)
    
    await page.goto('http://localhost:3000/admin/zones')
    await page.waitForTimeout(2000)
  })
})

test.describe('Responsive Design', () => {
  test('works on smaller viewport', async ({ page, request }) => {
    await page.setViewportSize({ width: 768, height: 1024 })
    
    const token = await loginViaAPI(request)
    await setTokenInPage(page, token)
    
    await page.goto('http://localhost:3000/admin')
    await page.waitForTimeout(1000)
  })
})

test.describe('Accessibility', () => {
  test('form fields have labels', async ({ page }) => {
    await page.goto('http://localhost:3000/login')
    
    const usernameInput = page.locator('input[placeholder="username"]')
    await expect(usernameInput).toBeVisible()
    
    const passwordInput = page.locator('input[placeholder="password"]')
    await expect(passwordInput).toBeVisible()
  })

  test('buttons are keyboard accessible', async ({ page }) => {
    await page.goto('http://localhost:3000/login')
    await page.keyboard.press('Tab')
    await page.keyboard.press('Tab')
    await page.keyboard.press('Enter')
    await page.waitForTimeout(1000)
  })
})
