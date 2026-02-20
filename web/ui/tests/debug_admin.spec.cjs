const { test } = require('@playwright/test')

test('debug admin page with token', async ({ page, request }) => {
  const res = await request.post('http://localhost:8080/api/v1/auth/login', { data: { username: 'admin', password: 'admin123' } })
  const body = await res.json()
  const token = body.token
  await page.addInitScript(token => { localStorage.setItem('token', token) }, token)

  await page.goto('http://localhost:3000/admin/zones')
  await page.waitForTimeout(1000)
  const html = await page.content()
  console.log('PAGE HTML SNIPPET:', html.slice(0,500))
  await page.screenshot({ path: 'debug_admin.png', fullPage: true })
})