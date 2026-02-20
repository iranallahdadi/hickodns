const { test } = require('@playwright/test')

test('debug login network/console', async ({ page }) => {
  page.on('console', msg => console.log('PAGE LOG:', msg.type(), msg.text()))
  page.on('request', req => console.log('REQUEST:', req.method(), req.url()))
  page.on('response', res => console.log('RESPONSE:', res.status(), res.url()))

  await page.goto('http://localhost:3000/')
  await page.click('text=Login')
  await page.fill('input[placeholder="username"]', 'admin')
  await page.fill('input[placeholder="password"]', 'admin123')

  // Try manual fetch from page context to see if calls work from browser
  const ping = await page.evaluate(async () => {
    try {
      const r = await fetch('/api/v1/auth/login', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ username: 'admin', password: 'admin123' }), credentials: 'omit' })
      return { status: r.status, ok: r.ok, text: await r.text() }
    } catch (e) { return { error: e.message } }
  })
  console.log('FETCH FROM PAGE:', ping)

  // Now click login button to run usual path
  await page.click('text=Login')
  // wait a bit
  await page.waitForTimeout(2000)
})
