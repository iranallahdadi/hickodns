const { test } = require('@playwright/test')

test('debug network after nav to records', async ({ page, request }) => {
  const res = await request.post('http://localhost:8080/api/v1/auth/login', { data: { username: 'admin', password: 'admin123' } })
  const body = await res.json()
  const token = body.token
  await page.addInitScript(token => { localStorage.setItem('token', token) }, token)

  page.on('request', req => console.log('REQ:', req.method(), req.url()))
  page.on('response', res => console.log('RES:', res.status(), res.url()))

  // Use a fixed zone id - create it first via API
  await request.post('http://localhost:8080/api/v1/zones', { data: { domain: `nav-test-${Date.now()}.test` }, headers: { Authorization: `Bearer ${token}` } })
  const zonesRes = await request.get('http://localhost:8080/api/v1/zones', { headers: { Authorization: `Bearer ${token}` } })
  const zones = await zonesRes.json()
  const latest = zones[zones.length - 1]
  const zoneId = latest.id

  await page.goto(`http://localhost:3000/admin/zones/${zoneId}/records`)
  await page.waitForTimeout(1500)
})