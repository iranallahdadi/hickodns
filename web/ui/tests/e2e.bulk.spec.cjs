const { test, expect } = require('@playwright/test')
const path = require('path')

test('login -> admin -> bulk import zones -> verify', async ({ page, request }) => {
  const res = await request.post('http://localhost:8080/api/v1/auth/login', { data: { username: 'admin', password: 'admin123' } })
  const body = await res.json()
  const token = body.token
  await page.addInitScript(token => { localStorage.setItem('token', token) }, token)

  await page.goto('http://localhost:3000/')
  await page.click('text=Admin')
  await page.click('text=Zones')

  // upload fixture
  const filePath = path.join(__dirname, 'fixtures', 'zones.csv')
  const input = await page.waitForSelector('input[type=file]')
  await input.setInputFiles(filePath)
  await page.click('text=Import')

  // wait for created entries to appear
  await page.waitForSelector('text=example-bulk.com')
  await page.waitForSelector('text=example-bulk2.com')
})

test('dark mode toggle persists', async ({ page, request }) => {
  const res = await request.post('http://localhost:8080/api/v1/auth/login', { data: { username: 'admin', password: 'admin123' } })
  const body = await res.json()
  const token = body.token
  await page.addInitScript(token => { localStorage.setItem('token', token) }, token)

  await page.goto('http://localhost:3000/')
  await page.click('text=Admin')
  // toggle dark
  await page.click('text=Dark')
  // ensure class present
  const hasDark = await page.evaluate(() => document.documentElement.classList.contains('dark'))
  expect(hasDark).toBe(true)
})
