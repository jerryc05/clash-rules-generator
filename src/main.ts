import * as fs from 'fs'
import * as path from 'path'
import { fileURLToPath } from 'url'
import * as YAML from 'yaml'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const ENABLE_DNS_HIJACK = true
const UNSAFE_NO_FALLBACK_DNS__FAST = true
const ENABLE_EXPERIMENTAL_BYPASS_DOMAINS = true

//
//
//
//
//

type MixinClashConfig = {
  bypass: string[] /// todo: not in mixin
  dns: {
    enable?: boolean
    ipv6: boolean
    listen: string
    'default-nameserver': string[]
    nameserver: string[]
    fallback?: string[]
    'fallback-filter'?: object
    'fake-ip-filter': string[]
  }
  tun: object
  'rule-providers': {
    [key: string]: {
      type: 'http'
      behavior: 'domain'
      url: string
      path: string
      interval: 86400 // 10 days
    }
  }
}

const mixinConfig: Readonly<MixinClashConfig> = {
  bypass: [
    'localhost',
    '127.*',
    '10.*',
    '172.16.*',
    '172.17.*',
    '172.18.*',
    '172.19.*',
    '172.20.*',
    '172.21.*',
    '172.22.*',
    '172.23.*',
    '172.24.*',
    '172.25.*',
    '172.26.*',
    '172.27.*',
    '172.28.*',
    '172.29.*',
    '172.30.*',
    '172.31.*',
    '192.168.*',
    '<local>',
  ],
  dns: {
    ipv6: true,
    listen: '127.0.0.1:53',
    'default-nameserver': [
      '1.1.1.1',
      '119.29.29.29',
      '223.5.5.5',
      '1.2.4.8',
      '114.114.114.114',
    ],
    nameserver: [
      // 'https://doh.pub/dns-query',
      'tls://dot.pub',
      // 'https://dns.alidns.com/dns-query',
      'tls://dns.alidns.com',
      // 'https://1.12.12.12/dns-query',
      'tls://1.12.12.12',
      // 'https://doh.360.cn/dns-query',
      'tls://doh.360.cn',
      // 'dhcp://en0',
    ],
    fallback: [
      // 将被用于解析国外域名
      // 'https://cloudflare-dns.com/dns-query',
      'tls://one.one.one.one',
      // 'https://dns.google/dns-query',
      'tls://dns.google',
      // 'https://dns.quad9.net/dns-query',
      'tls://dns.quad9.net',
    ],
    'fallback-filter': {
      geoip: true,
      'geoip-code': 'CN',
      ipcidr: [
        // 被屏蔽的域名解析常常会被污染到这一段
        '240.0.0.0/4',
      ],
    },
    'fake-ip-filter': [
      '*.lan',
      'localhost.*',
      '+.stun.*.*',
      '+.stun.*.*.*',
      '+.stun.*.*.*.*',
      '+.stun.*.*.*.*.*',
      '*.n.n.srv.nintendo.net',
      '+.stun.playstation.net',
      'xbox.*.*.microsoft.com',
      '*.*.xboxlive.com',
      '*.msftncsi.com',
      '*.msftconnecttest.com',
      'WORKGROUP',
    ],
  },
  tun: {
    stack: 'system',
  },
  'rule-providers': YAML.parse(
    // https://github.com/Loyalsoldier/clash-rules
    `
rule-providers:
  ⛔️广告域名:
    type: http
    behavior: domain
    url: "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/reject.txt"
    path: ./rule-providers/github/Loyalsoldier/reject.yaml
    interval: 86400

  ✅iCloud直连:
    type: http
    behavior: domain
    url: "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/icloud.txt"
    path: ./rule-providers/github/Loyalsoldier/icloud.yaml
    interval: 86400

  ✅🍎直连:
    type: http
    behavior: domain
    url: "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/apple.txt"
    path: ./rule-providers/github/Loyalsoldier/apple.yaml
    interval: 86400

  ✅google直连⚠️慎用:
    type: http
    behavior: domain
    url: "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/google.txt"
    path: ./rule-providers/github/Loyalsoldier/google.yaml
    interval: 86400

  🚀需要梯子的域名:
    type: http
    behavior: domain
    url: "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/proxy.txt"
    path: ./rule-providers/github/Loyalsoldier/proxy.yaml
    interval: 86400

  ✅可直连域名:
    type: http
    behavior: domain
    url: "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/direct.txt"
    path: ./rule-providers/github/Loyalsoldier/direct.yaml
    interval: 86400

  ✅私有网络域名:
    type: http
    behavior: domain
    url: "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/private.txt"
    path: ./rule-providers/github/Loyalsoldier/private.yaml
    interval: 86400

  🚀GFWList被墙域名:
    type: http
    behavior: domain
    url: "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/gfw.txt"
    path: ./rule-providers/github/Loyalsoldier/gfw.yaml
    interval: 86400

  🚀非大陆使用的顶级域名:
    type: http
    behavior: domain
    url: "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/tld-not-cn.txt"
    path: ./rule-providers/github/Loyalsoldier/tld-not-cn.yaml
    interval: 86400

  🚀✈️Telegram_CIDR:
    type: http
    behavior: ipcidr
    url: "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/telegramcidr.txt"
    path: ./rule-providers/github/Loyalsoldier/telegramcidr.yaml
    interval: 86400

  ✅大陆IP_CIDR:
    type: http
    behavior: ipcidr
    url: "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/cncidr.txt"
    path: ./rule-providers/github/Loyalsoldier/cncidr.yaml
    interval: 86400

  ✅局域网或保留IP_CIDR:
    type: http
    behavior: ipcidr
    url: "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/lancidr.txt"
    path: ./rule-providers/github/Loyalsoldier/lancidr.yaml
    interval: 86400

  ✅可直连常见应用:
    type: http
    behavior: classical
    url: "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/applications.txt"
    path: ./rule-providers/github/Loyalsoldier/applications.yaml
    interval: 86400`
  )['rule-providers'],
}
// ENABLE_DNS
if (ENABLE_DNS_HIJACK) mixinConfig.dns.enable = true
// DISABLE_FALLBACK_DNS
if (UNSAFE_NO_FALLBACK_DNS__FAST) {
  delete mixinConfig.dns['fallback-filter']
  mixinConfig.dns.nameserver.push(...(mixinConfig.dns.fallback || []))
  delete mixinConfig.dns.fallback
}
// ENABLE_EXPERIMENTAL_BYPASS_DOMAINS
if (ENABLE_EXPERIMENTAL_BYPASS_DOMAINS) {
  mixinConfig['bypass'].unshift(
    'local.teams.office.com',
    '*blizzard.com' /* battle.net download cdn */,
    'xz.pphimalayanrt.com' /* steam download cdn */,
    ...mixinConfig.dns['fake-ip-filter']
  )
}

if (mixinConfig.bypass[mixinConfig.bypass.length - 1] != '<local>')
  throw new Error('<local> must be the last item in [bypass]!')
fs.promises.writeFile('mixin.yaml', YAML.stringify({ mixin: mixinConfig }))

//
//
//
//
//

type ClashConfig = {
  proxies?: {
    name: string
    type: 'ss' | 'ssr' | 'vmess' | 'trojan' | 'socks5'
    server: string
    port: number
    cipher: 'auto' | 'chacha20-ietf-poly1305'
    password: string
    udp: boolean
  }[]
  'proxy-groups':
    | ((
        | { type: 'select' | 'url-test' | 'fallback' }
        | {
            type: 'load-balance'
            strategy?: 'consistent-hashing' | 'round-robin'
          }
      ) &
        ({ proxies: string[] } | { use: string[] }) & {
          name: string
          url: 'http://www.google.com/generate_204'
          interval: 300
          lazy: true
        })[]
  'proxy-providers'?: {
    [key: string]: (
      | {
          type: 'http'
          url: string
        }
      | {
          type: 'file'
        }
    ) & {
      path: string
      interval: number
      filter?: string // remove the proxy that does not match the filter, separated by |
      'health-check': {
        enable: true
        url: 'http://www.google.com/generate_204'
        interval: 600
      }
    }
  }

  rules: string[]
}

const config: ClashConfig = {
  rules: [],
  'proxy-groups': [],
}

//
//
//
//
//

// ♻️ 自动选择

const DEFAULT_PROXY_NAME = '🚀️默认梯子线路🪜'

function createProxyGroupPlaceholder(name: string) {
  const x: Pick<
    ClashConfig['proxy-groups'][0],
    'name' | 'url' | 'interval' | 'lazy'
  > = {
    name,
    url: 'http://www.google.com/generate_204',
    interval: 300,
    lazy: true,
  }
  return x
}

function getDefaultProxyGroup() {
  const group = config['proxy-groups'].find(x => x.name === DEFAULT_PROXY_NAME)
  if (group) return group

  const newGroup: ClashConfig['proxy-groups'][0] = {
    ...createProxyGroupPlaceholder(DEFAULT_PROXY_NAME),
    type: 'select',
    proxies: [],
  }
  config['proxy-groups'].push(newGroup)
  return newGroup
}

// proxy-providers
{
  function addUrlProxyProvider(name: string, url: string) {
    if (config['proxy-providers'] == null) config['proxy-providers'] = {}
    config['proxy-providers'][name] = {
      type: 'http',
      url,
      path: `./proxy-providers/${name}.yaml`,
      interval: 21600,
      'health-check': {
        enable: true,
        url: 'http://www.google.com/generate_204',
        interval: 600,
      },
    }
  }

  addUrlProxyProvider(
    'cyanmori',
    fs
      .readFileSync(path.resolve(__dirname, 'dont-sync/cyanmori.txt'), 'utf-8')
      .trim()
  )

  addUrlProxyProvider(
    'github/mahdibland/V2RayAggregator',
    'https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity.yml'
  )
}

function validateRulesAndProviders() {
  const rule_providers_names = Object.keys(mixinConfig['rule-providers'] || {})
  const rules_names = config.rules
    .filter(x => x.startsWith('RULE-SET,') /* || x.startsWith('MATCH,') */)
    .map(x => x.split(',')[1])

  const only_in_rule_providers = rule_providers_names.filter(
    x => !rules_names.includes(x)
  )
  if (only_in_rule_providers.length > 0) {
    throw new Error(
      `These rules are defined in rule-providers but not assigned in rules: ${only_in_rule_providers}`
    )
  }

  const only_in_rules = rules_names.filter(
    x => !rule_providers_names.includes(x)
  )
  if (only_in_rules.length > 0) {
    throw new Error(
      `These rules are assigned in rules but not defined in rule-providers: ${only_in_rules}`
    )
  }
}

function validateRulesAndProxyGroups() {
  const rules_proxies = new Set(
    config.rules.map(x => x.split(',').pop() as string)
  )
  const proxy_groups_names = new Set(
    (config['proxy-groups'] || []).map(x => x.name).concat(['DIRECT', 'REJECT'])
  )

  const only_in_rules_proxies = [...rules_proxies].filter(
    x => !proxy_groups_names.has(x)
  )
  if (only_in_rules_proxies.length > 0) {
    throw new Error(
      `These proxies are defined in rules but not used in proxy-groups: ${only_in_rules_proxies}`
    )
  }

  const only_in_proxy_groups_names = [...proxy_groups_names].filter(
    x => !rules_proxies.has(x)
  )
  if (only_in_proxy_groups_names.length > 0) {
    throw new Error(
      `These proxies are used in proxy-groups but not defined in rules: ${only_in_proxy_groups_names}`
    )
  }
}

// rules
{
  // https://github.com/Loyalsoldier/clash-rules
  {
    config.rules = YAML.parse(`
rules:
  - RULE-SET,✅可直连域名,DIRECT
  - RULE-SET,✅局域网或保留IP_CIDR,DIRECT
  - RULE-SET,✅私有网络域名,DIRECT
  - GEOIP,LAN,DIRECT
  - RULE-SET,✅🍎直连,DIRECT
  - RULE-SET,✅iCloud直连,DIRECT
  - RULE-SET,✅可直连常见应用,DIRECT
  - RULE-SET,✅大陆IP_CIDR,DIRECT
  - GEOIP,CN,DIRECT
  - RULE-SET,✅google直连⚠️慎用,DIRECT
  - RULE-SET,⛔️广告域名,⛔️广告拦截
  - RULE-SET,🚀需要梯子的域名,默认代理
  - RULE-SET,🚀✈️Telegram_CIDR,默认代理
  - RULE-SET,🚀GFWList被墙域名,默认代理
  - RULE-SET,🚀非大陆使用的顶级域名,默认代理`).rules

    validateRulesAndProviders()
  }

  // Discord BLOCKED
  {
    const group_name = '🎮Discord_已被墙域名'
    ;[
      'discord.com',
      'gateway.discord.gg' /* must before [discord.gg] */,
      'discordapp.com',
      'discordapp.net',
      'discordstatus.com',
    ].forEach(x => {
      config.rules.push(`DOMAIN-SUFFIX,${x},${group_name}`)
    })
    // config['proxy-groups'].push({
    //   name: group_name,
    //   type: 'select',
    //   proxies: [],
    //   use: [],
    // })
  }

  // Discord NOT_BLOCKED
  {
    const group_name = '🎮Discord_可直连域名'
    ;['discord.gg', 'discord.media'].forEach(x => {
      config.rules.push(`DOMAIN-SUFFIX,${x},${group_name}`)
    })
    // config['proxy-groups'].push({
    //   name: group_name,
    //   type: 'select',
    //   proxies: [],
    //   use: [],
    // })
  }

  // Duo Security
  {
    const group_name = '🔒DuoSecurity'
    ;['duosecurity.com', 'duo.com'].forEach(x => {
      config.rules.push(`DOMAIN-SUFFIX,${x},${group_name}`)
    })
    // config['proxy-groups'].push({
    //   name: group_name,
    //   type: 'select',
    //   proxies: [],
    //   use: [],
    // })
  }

  // Wechat
  {
    const group_name = '💬WeChat'
    ;['wechat.com', 'weixin.qq.com', 'weixinbridge.com'].forEach(x => {
      config.rules.push(`DOMAIN-SUFFIX,${x},${group_name}`)
    })
    // config['proxy-groups'].push({
    //   name: group_name,
    //   type: 'select',
    //   proxies: [],
    //   use: [],
    // })
  }

  // Tencent
  {
    const group_name = '💬Tencent'
    ;['qq.com', 'qpic.cn'].forEach(x => {
      config.rules.push(`DOMAIN-SUFFIX,${x},${group_name}`)
    })
    // config['proxy-groups'].push({
    //   name: group_name,
    //   type: 'select',
    //   proxies: [],
    //   use: [],
    // })
  }

  // Zhihu
  {
    const group_name = '💬知乎'
    ;['zhihu.com', 'zhing.com'].forEach(x => {
      config.rules.push(`DOMAIN-SUFFIX,${x},${group_name}`)
    })
    // config['proxy-groups'].push({
    //   name: group_name,
    //   type: 'select',
    //   proxies: [],
    //   use: [],
    // })
  }

  // Google NOT_BLOCKED
  {
    const group_name = '🚀Google_可直连'
    ;['dl.google.com' /* must before [google.com] */].forEach(x => {
      config.rules.push(`DOMAIN-SUFFIX,${x},${group_name}`)
    })
    // config['proxy-groups'].push({
    //   name: group_name,
    //   type: 'select',
    //   proxies: [],
    //   use: [],
    // })
  }

  // Google BLOCKED
  {
    const group_name = '🚀Google_已被墙'
    ;[
      'google.com',
      'googleapis.com',
      'googleusercontent.com',
      'webpkgcache.com',
    ].forEach(x => {
      config.rules.push(`DOMAIN-SUFFIX,${x},${group_name}`)
    })
    // config['proxy-groups'].push({
    //   name: group_name,
    //   type: 'select',
    //   proxies: [],
    //   use: [],
    // })
  }

  {
    const domains: {
      [key: string]: { [key: string]: Set<string> }
    } = {
      '🎬Youtube': {
        'DOMAIN-SUFFIX': new Set([
          // https://www.netify.ai/resources/applications/youtube
          'googlevideo.com',
          'gvt1.com',
          'video.google.com',
          'video.l.google.com',
          'youtu.be',
          'youtube-nocookie.com',
          'youtube-ui.l.google.com',
          'youtube.ae',
          'youtube.al',
          'youtube.am',
          'youtube.at',
          'youtube.az',
          'youtube.ba',
          'youtube.be',
          'youtube.bg',
          'youtube.bh',
          'youtube.bo',
          'youtube.by',
          'youtube.ca',
          'youtube.cat',
          'youtube.ch',
          'youtube.cl',
          'youtube.co',
          'youtube.co.ae',
          'youtube.co.at',
          'youtube.co.cr',
          'youtube.co.hu',
          'youtube.co.id',
          'youtube.co.il',
          'youtube.co.in',
          'youtube.co.jp',
          'youtube.co.ke',
          'youtube.co.kr',
          'youtube.co.ma',
          'youtube.co.nz',
          'youtube.co.th',
          'youtube.co.tz',
          'youtube.co.ug',
          'youtube.co.uk',
          'youtube.co.ve',
          'youtube.co.za',
          'youtube.co.zw',
          'youtube.com',
          'youtube.com.ar',
          'youtube.com.au',
          'youtube.com.az',
          'youtube.com.bd',
          'youtube.com.bh',
          'youtube.com.bo',
          'youtube.com.br',
          'youtube.com.by',
          'youtube.com.co',
          'youtube.com.do',
          'youtube.com.ec',
          'youtube.com.ee',
          'youtube.com.eg',
          'youtube.com.es',
          'youtube.com.gh',
          'youtube.com.gr',
          'youtube.com.gt',
          'youtube.com.hk',
          'youtube.com.hn',
          'youtube.com.hr',
          'youtube.com.jm',
          'youtube.com.jo',
          'youtube.com.kw',
          'youtube.com.lb',
          'youtube.com.lv',
          'youtube.com.ly',
          'youtube.com.mk',
          'youtube.com.mt',
          'youtube.com.mx',
          'youtube.com.my',
          'youtube.com.ng',
          'youtube.com.ni',
          'youtube.com.om',
          'youtube.com.pa',
          'youtube.com.pe',
          'youtube.com.ph',
          'youtube.com.pk',
          'youtube.com.pt',
          'youtube.com.py',
          'youtube.com.qa',
          'youtube.com.ro',
          'youtube.com.sa',
          'youtube.com.sg',
          'youtube.com.sv',
          'youtube.com.tn',
          'youtube.com.tr',
          'youtube.com.tw',
          'youtube.com.ua',
          'youtube.com.uy',
          'youtube.com.ve',
          'youtube.cr',
          'youtube.cz',
          'youtube.de',
          'youtube.dk',
          'youtube.ee',
          'youtube.es',
          'youtube.fi',
          'youtube.fr',
          'youtube.ge',
          'youtube.googleapis.com',
          'youtube.gr',
          'youtube.gt',
          'youtube.hk',
          'youtube.hr',
          'youtube.hu',
          'youtube.ie',
          'youtube.in',
          'youtube.iq',
          'youtube.is',
          'youtube.it',
          'youtube.jo',
          'youtube.jp',
          'youtube.kr',
          'youtube.kz',
          'youtube.la',
          'youtube.lk',
          'youtube.lt',
          'youtube.lu',
          'youtube.lv',
          'youtube.ly',
          'youtube.ma',
          'youtube.md',
          'youtube.me',
          'youtube.mk',
          'youtube.mn',
          'youtube.mx',
          'youtube.my',
          'youtube.ng',
          'youtube.ni',
          'youtube.nl',
          'youtube.no',
          'youtube.pa',
          'youtube.pe',
          'youtube.ph',
          'youtube.pk',
          'youtube.pl',
          'youtube.pr',
          'youtube.pt',
          'youtube.qa',
          'youtube.ro',
          'youtube.rs',
          'youtube.ru',
          'youtube.sa',
          'youtube.se',
          'youtube.sg',
          'youtube.si',
          'youtube.sk',
          'youtube.sn',
          'youtube.soy',
          'youtube.sv',
          'youtube.tn',
          'youtube.tv',
          'youtube.ua',
          'youtube.ug',
          'youtube.uy',
          'youtube.vn',
          'youtubeeducation.com',
          'youtubeembeddedplayer.googleapis.com',
          'youtubei.googleapis.com',
          'youtubekids.com',
          'yt-video-upload.l.google.com',
          'yt.be',
          'yt3.ggpht.com',
          'ytimg.com',
          'ytimg.l.google.com',
          'ytkids.app.goo.gl',
          'video-stats.l.google.com',
          'youtube',
        ]),
      },
      '🎥Netflix': {
        'DOMAIN-SUFFIX': new Set([
          // https://www.netify.ai/resources/applications/netflix
          'flxvpn.net',
          'netflix.ca',
          'netflix.com',
          'netflix.com.au',
          'netflix.net',
          'netflixdnstest0.com',
          'netflixdnstest1.com',
          'netflixdnstest10.com',
          'netflixdnstest2.com',
          'netflixdnstest3.com',
          'netflixdnstest4.com',
          'netflixdnstest5.com',
          'netflixdnstest6.com',
          'netflixdnstest7.com',
          'netflixdnstest8.com',
          'netflixdnstest9.com',
          'netflixinvestor.com',
          'netflixstudios.com',
          'netflixtechblog.com',
          'nflxext.com',
          'nflximg.com',
          'nflximg.net',
          'nflxso.net',
          'nflxvideo.net',
          // https://www.netify.ai/resources/applications/netflix-cdn
          'nflxvideo.net',
        ]),
        // https://asnlookup.com/asn/AS2906/
        'IP-CIDR': new Set([
          '23.246.0.0/18',
          '37.77.184.0/21',
          '45.57.0.0/21',
          '45.57.10.0/23',
          '45.57.12.0/22',
          '45.57.16.0/20',
          '45.57.32.0/21',
          '45.57.42.0/23',
          '45.57.44.0/22',
          '45.57.48.0/20',
          '45.57.64.0/21',
          '45.57.72.0/22',
          '45.57.78.0/23',
          '45.57.80.0/22',
          '45.57.84.0/23',
          '45.57.88.0/23',
          '45.57.92.0/22',
          '45.57.96.0/19',
          '64.120.128.0/17',
          '66.197.128.0/17',
          '69.53.224.0/22',
          '69.53.228.0/24',
          '69.53.230.0/23',
          '69.53.232.0/21',
          '69.53.240.0/20',
          '108.175.32.0/20',
          '185.2.220.0/22',
          '185.9.188.0/22',
          '192.173.64.0/19',
          '192.173.96.0/23',
          '192.173.100.0/22',
          '192.173.104.0/21',
          '192.173.112.0/20',
          '198.38.96.0/19',
          '198.45.48.0/20',
          '208.75.76.0/22',
        ]),
        'IP-CIDR6': new Set([
          '2607:fb10::/35',
          '2607:fb10:2000::/43',
          '2607:fb10:2020::/44',
          '2607:fb10:2030::/47',
          '2607:fb10:2032::/48',
          '2607:fb10:2035::/48',
          '2607:fb10:2036::/47',
          '2607:fb10:2038::/45',
          '2607:fb10:2040::/47',
          '2607:fb10:2043::/48',
          '2607:fb10:2044::/46',
          '2607:fb10:2048::/45',
          '2607:fb10:2050::/44',
          '2607:fb10:2060::/43',
          '2607:fb10:2080::/41',
          '2607:fb10:2100::/40',
          '2607:fb10:2200::/39',
          '2607:fb10:2400::/38',
          '2607:fb10:2800::/37',
          '2607:fb10:3000::/36',
          '2607:fb10:4000::/35',
          '2607:fb10:6000::/36',
          '2607:fb10:7000::/41',
          '2607:fb10:7080::/42',
          '2607:fb10:70c0::/43',
          '2607:fb10:70e0::/44',
          '2607:fb10:7100::/40',
          '2607:fb10:7200::/39',
          '2607:fb10:7400::/38',
          '2607:fb10:7800::/37',
          '2607:fb10:8000::/33',
          '2620:10c:7000::/44',
          '2a00:86c0::/35',
          '2a00:86c0:2000::/45',
          '2a00:86c0:200a::/47',
          '2a00:86c0:200c::/46',
          '2a00:86c0:2010::/44',
          '2a00:86c0:2020::/43',
          '2a00:86c0:2042::/47',
          '2a00:86c0:2044::/46',
          '2a00:86c0:2048::/45',
          '2a00:86c0:2050::/44',
          '2a00:86c0:2060::/44',
          '2a00:86c0:2070::/46',
          '2a00:86c0:2074::/47',
          '2a00:86c0:2078::/45',
          '2a00:86c0:2080::/46',
          '2a00:86c0:2084::/47',
          '2a00:86c0:2088::/45',
          '2a00:86c0:2092::/47',
          '2a00:86c0:2094::/46',
          '2a00:86c0:2098::/45',
          '2a00:86c0:20a0::/43',
          '2a00:86c0:20c0::/42',
          '2a00:86c0:2100::/40',
          '2a00:86c0:2200::/39',
          '2a00:86c0:2400::/38',
          '2a00:86c0:2800::/37',
          '2a00:86c0:3000::/36',
          '2a00:86c0:4000::/34',
          '2a00:86c0:8000::/33',
          '2a03:5640::/33',
          '2a03:5640:8000::/34',
          '2a03:5640:c000::/35',
          '2a03:5640:e000::/36',
          '2a03:5640:f041::/48',
          '2a03:5640:f043::/48',
          '2a03:5640:f044::/48',
          '2a03:5640:f047::/48',
          '2a03:5640:f048::/45',
          '2a03:5640:f050::/44',
          '2a03:5640:f060::/43',
          '2a03:5640:f080::/41',
          '2a03:5640:f140::/47',
          '2a03:5640:f142::/48',
          '2a03:5640:f146::/47',
          '2a03:5640:f148::/45',
          '2a03:5640:f150::/44',
          '2a03:5640:f160::/43',
          '2a03:5640:f180::/41',
          '2a03:5640:f229::/48',
          '2a03:5640:f22a::/47',
          '2a03:5640:f22c::/46',
          '2a03:5640:f230::/44',
          '2a03:5640:f240::/42',
          '2a03:5640:f280::/41',
          '2a03:5640:f300::/47',
          '2a03:5640:f303::/48',
          '2a03:5640:f304::/46',
          '2a03:5640:f308::/45',
          '2a03:5640:f310::/44',
          '2a03:5640:f320::/43',
          '2a03:5640:f340::/42',
          '2a03:5640:f380::/41',
          '2a03:5640:f400::/40',
          '2a03:5640:f501::/48',
          '2a03:5640:f506::/48',
          '2a03:5640:f51c::/46',
          '2a03:5640:f520::/44',
          '2a03:5640:f533::/48',
          '2a03:5640:f534::/46',
          '2a03:5640:f538::/45',
          '2a03:5640:f540::/43',
          '2a03:5640:f561::/48',
          '2a03:5640:f562::/47',
          '2a03:5640:f564::/46',
          '2a03:5640:f568::/45',
          '2a03:5640:f570::/44',
          '2a03:5640:f580::/41',
          '2a03:5640:f600::/39',
          '2a03:5640:f800::/37',
        ]),
      },
      '💬OpenAI-(ChatGPT)': {
        'DOMAIN-SUFFIX': new Set(['openai.com']),
      },
      '🎵Spotify': {
        'DOMAIN-SUFFIX': new Set([
          // https://www.netify.ai/resources/applications/spotify
          'pscdn.co',
          'scdn.co',
          'spoti.fi',
          'spotify.com',
          'spotifycdn.com',
          'spotifycdn.net',
          'spotifycharts.com',
          'spotifycodes.com',
          'spotifyjobs.com',
          'spotifynewsroom.jp',
          'spotilocal.com',
          'tospotify.com',

          // other
          'byspotify.com',
          'pscdn.co',
          'scdn.co',
          'spoti.fi',
          'spotify-everywhere.com',
          'spotify.com',
          'spotify.design',
          'spotifycdn.com',
          'spotifycdn.net',
          'spotifycharts.com',
          'spotifycodes.com',
          'spotifyforbrands.com',
          'spotifyjobs.com',
          'audio-ak-spotify-com.akamaized.net',
          'heads4-ak-spotify-com.akamaized.net',
        ]),
      },
      '✈️Telegram': {
        'DOMAIN-SUFFIX': new Set([
          // https://www.netify.ai/resources/applications/telegram
          't.me',
          'telegram.me',
          'telegram.org',
          'telesco.pe',
          'tg.dev',
          // other
          'tdesktop.com',
          'telegra.ph',
        ]),
        'IP-CIDR': new Set([
          // https://asnlookup.com/organization/Telegram%20Messenger%20Inc/
          '91.108.4.0/22',
          '91.108.8.0/22',
          '91.108.58.0/23',
          '95.161.64.0/20',
          '149.154.160.0/21',
          '91.105.192.0/23',
          '185.76.151.0/24',
          '91.108.20.0/22',
          '91.108.12.0/22',
          '149.154.172.0/22',
          '91.108.16.0/22',
          '91.108.56.0/23',
          '149.154.168.0/22',
        ]),
        'IP-CIDR6': new Set([
          // https://asnlookup.com/organization/Telegram%20Messenger%20Inc/
          '2001:67c:4e8::/48',
          '2a0a:f280:203::/48',
          '2001:b28:f23c::/48',
          '2001:b28:f23d::/48',
          '2001:b28:f23f::/48',
        ]),
      },
      '🎥Disney+': {
        'DOMAIN-SUFFIX': new Set([
          // https://www.netify.ai/resources/applications/disney-plus
          'disney-plus.net',
          'disney-vod-na-west-1.top.comcast.net',
          'disneyplus.com',
          'disneyplus.disney.co.jp',
          'disneystreaming.service-now.com',
          'dssott.com',
          'search-api-disney.bamgrid.com',
          'starott.com',
          // other
          'disneyplus.com',
          'disney-plus.net',
          'disneystreaming.com',
          'dssott.com',
          'bamgrid.com',
          'playback-certs.bamgrid.com',
          'disney.api.edge.bamgrid.com',
          'disney.connections.edge.bamgrid.com',
          'disney.content.edge.bamgrid.com',
          'disney.playback.edge.bamgrid.com',
          'cdn.registerdisney.go.com',
          // 'execute-api.us-east-1.amazonaws.com',
          'sanalytics.disnyplus.com',
        ]),
      },
      '🎬Bilibili': {
        'DOMAIN-SUFFIX': new Set([
          'biliapi.com',
          'biliapi.net',
          'bilibili.com',
          'bilibili.tv',
          'bilivideo.com',
        ]),
      },
      '🎮Steam-(BLOCKED)': {
        'DOMAIN-SUFFIX': new Set([
          'steamcommunity.com',
          'api.steampowered.com',
          'store.steampowered.com',
          'ipv6check-http.steamserver.net',
        ]),
      },
      '🎮Steam-CDN': {
        'DOMAIN-SUFFIX': new Set([
          'cdn.steamcontent.com',
          'steamcdn-a.akamaihd.net',
        ]),
      },
      '🎮Steam-(NOT_BLOCKED)': {
        'DOMAIN-SUFFIX': new Set([
          // https://www.netify.ai/resources/applications/steam
          's.team',
          'steam-chat.com',
          'steamchina.com',
          'steamcontent.com',
          'steamgames.com',
          'steampowered.com',
          'steampowered.com.8686c.com',
          'steamserver.net',
          'steamstatic.com',
          'steamstatic.com.8686c.com',
          'steamusercontent.com',
          'steamstat.us',
        ]),
      },
    }

    Object.entries(domains).forEach(([name, pattern_and_infos]) => {
      Object.entries(pattern_and_infos).forEach(([pattern, infos]) => {
        infos.forEach(info => {
          config.rules.push(
            `${pattern},${info},${name}${
              pattern.startsWith('IP-CIDR') ? ',no-resolve' : ''
            }`
          )
        })
      })
    })
  }

  // Microsoft
  {
    const group_name = 'Ⓜ️Microsoft_可直连'

    ;['trafficmanager.net', 'officecdn-microsoft-com.akamaized.net'].forEach(
      x => {
        config.rules.push(`DOMAIN-SUFFIX,${x},${group_name}`)
      }
    )
    // config['proxy-groups'].push({
    //   name: group_name,
    //   type: 'select',
    //   proxies: [],
    //   use: [],
    // })
  }

  // Overwatch
  {
    const group_name = '🎮Overwatch'
    ;['Overwatch.exe'].forEach(x => {
      config.rules.push(`PROCESS-NAME,${x},${group_name}`)
    })
    config['proxy-groups'].push({
      ...createProxyGroupPlaceholder(group_name),
      type: 'select',
      proxies: ['DIRECT'],
    })
  }

  // Battle.net speed up
  {
    const group_name = '🎮Battle.net_加速'
    ;['us.battle.net'].forEach(x => {
      config.rules.push(`DOMAIN-SUFFIX,${x},${group_name}`)
    })
    // config['proxy-groups'].push({
    //   ...createProxyGroupPlaceholder(group_name),
    //   type: 'select',
    //   proxies: ['DIRECT'],
    // })
  }

  // Blizzard CDN
  {
    const group_name = '🎮Blizzard_(Battle.net)-CDN'
    ;[
      'cdn.blizzard.com',
      'level3.blizzard.com',
      'blz-contentstack-images.akamaized.net',
      'bnetcmsus-a.akamaihd.net',
      //
      'blzddist1-a.akamaihd.net',
    ].forEach(x => {
      config.rules.push(`DOMAIN-SUFFIX,${x},${group_name}`)
    })
    config['proxy-groups'].push({
      ...createProxyGroupPlaceholder(group_name),
      type: 'select',
      proxies: ['DIRECT'],
    })
  }

  // Vercel
  {
    const group_name = '🚀vercel.app'
    ;['vercel.app'].forEach(x => {
      config.rules.push(`DOMAIN-SUFFIX,${x},${group_name}`)
    })
    // config['proxy-groups'].push({
    //   name: group_name,
    //   type: 'select',
    //   proxies: [],
    //   use: [],
    // })
  }

  // LinkedIn
  {
    const group_name = '🧑‍💼LinkedIn'
    ;['linkedin.com'].forEach(x => {
      config.rules.push(`DOMAIN-SUFFIX,${x},${group_name}`)
    })
    // config['proxy-groups'].push({
    //   name: group_name,
    //   type: 'select',
    //   proxies: [],
    //   use: [],
    // })
  }

  // Github BLOCKED
  {
    const group_name = '🐙GitHub_已被墙'
    ;['github.blog', 'gist.github.com'].forEach(x => {
      config.rules.push(`DOMAIN-SUFFIX,${x},${group_name}`)
    })
    // config['proxy-groups'].push({
    //   name: group_name,
    //   type: 'select',
    //   proxies: [],
    //   use: [],
    // })
  }

  // Github speed up
  {
    const group_name = '🐙GitHub_加速'
    ;['github.githubassets.com'].forEach(x => {
      config.rules.push(`DOMAIN-SUFFIX,${x},${group_name}`)
    })
    ;['github.com' /* must before [DOMAIN-SUFFIX,github.com] */].forEach(x => {
      config.rules.push(`DOMAIN,${x},${group_name}`)
    })
    // config['proxy-groups'].push({
    //   name: group_name,
    //   type: 'select',
    //   proxies: [],
    //   use: [],
    // })
  }

  // Github NOT_BLOCKED
  {
    const group_name = '🐙GitHub_可能可直连'
    ;['github.dev', 'githubassets.com', 'github.com'].forEach(x => {
      config.rules.push(`DOMAIN-SUFFIX,${x},${group_name}`)
    })
    // config['proxy-groups'].push({
    //   name: group_name,
    //   type: 'select',
    //   proxies: [],
    //   use: [],
    // })
  }

  // misc
  {
    const group_name = '🔧Misc-(BLOCKED)'
    ;[
      'gravatar.com',
      'fanqiangdang.com',
      'digwebinterface.com',
      'v2ex.com',
    ].forEach(x => {
      config.rules.push(`DOMAIN-SUFFIX,${x},${group_name}`)
    })
    // config['proxy-groups'].push({
    //   name: group_name,
    //   type: 'select',
    //   proxies: [],
    //   use: [],
    // })
  }

  config.rules.push('MATCH,🐟漏网之鱼')
}
// console.log(JSON.stringify(config, null, 2))

await fs.promises.writeFile('my-config.yaml', YAML.stringify(config))

validateRulesAndProviders()
validateRulesAndProxyGroups()
