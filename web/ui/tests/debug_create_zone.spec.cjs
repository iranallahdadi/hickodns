const { test } = require('@playwright/test')

test('debug create zone network', async ({ page, request }) => {
  page.on('console', msg => console.log('PAGE LOG:', msg.type(), msg.text()))
  page.on('request', req => console.log('REQUEST:', req.method(), req.url()))
  page.on('response', res => console.log('RESPONSE:', res.status(), res.url()))

  const res = await request.post('http://localhost:8080/api/v1/auth/login', { data: { username: 'admin', password: 'admin123' } })
  const body = await res.json()
  const token = body.token
  await page.addInitScript(token => { localStorage.setItem('token', token) }, token)

  await page.goto('http://localhost:3000/')
  await page.waitForSelector('text=Admin')
  await page.click('text=Admin')
  await page.click('text=Zones')

  await page.waitForSelector('input[placeholder="domain"]')
  await page.fill('input[placeholder="domain"]', 'debug-example.com')
  await page.click('text=Create Zone')
  await page.waitForTimeout(2000)
})