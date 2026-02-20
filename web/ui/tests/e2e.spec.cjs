const { test, expect } = require('@playwright/test')

test('login -> create zone -> add record', async ({ page, request }) => {
  // Programmatic login via API to avoid flaky UI login behavior
  const res = await request.post('http://localhost:8080/api/v1/auth/login', { data: { username: 'admin', password: 'admin123' } })
  const body = await res.json()
  const token = body.token
  await page.addInitScript(token => { localStorage.setItem('token', token) }, token)

  await page.goto('http://localhost:3000/')
  await page.waitForSelector('text=Admin')
  await page.click('text=Admin')
  await page.click('text=Zones')

  await page.waitForSelector('input[placeholder="domain"]')
  await page.fill('input[placeholder="domain"]', 'example.com')
  await page.click('text=Create Zone')
  await page.waitForSelector('text=example.com')

  // navigate to manage records
  // Use client-side navigation to avoid full page reloads
  const manageLink = await page.locator('tbody tr').filter({ hasText: 'example.com' }).locator('text=Manage Records').first()
  const href = await manageLink.getAttribute('href')
  await page.evaluate(h => { history.pushState({}, '', h); window.dispatchEvent(new PopStateEvent('popstate')) }, href)
  // Ensure records page is rendered
  await page.waitForSelector('input[placeholder="name"]', { timeout: 10000 })

  await page.fill('input[placeholder="name"]', 'www')
  await page.fill('input[placeholder="value"]', '192.0.2.1')
  await page.click('text=Create Record')
  await page.waitForSelector('text=www')
})
