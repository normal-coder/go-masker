/*
Copyright © 2022 诺墨 <normal@normalcoder.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package regRule

var (
	partIPv4 = `(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])`
	Email    = `([_a-z0-9-]+)@([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9]))?((?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?){1,3}\s*)(?i)`
	Phone    = `(0|\+?86)?(13[0-9]|14[579]|15[0-9]|17[0135678]|18[0-9]|16[56]|19[189])[0-9]{8}`
	IPv4     = partIPv4 + "\\." + partIPv4 + "\\." + partIPv4 + "\\." + partIPv4
	All      = map[string]string{
		"Email": Email,
		"Phone": Phone,
		"IPv4":  IPv4,
	}
)

//Email = `(^[a-zA-Z0-9.!#$%&'*+/=?^_{|}~-]+)` + // 邮箱前缀
//	`@([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9]))?` + // 域名段
//	`((?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$)` // 顶级域段
//Email = `([^\s@]+)@([^\s@.]+)(\.[^\s@]+)`
// `[\w.-]+@[\w_-]+\w{1,}[\.\w-]+`
//Phone = `(0|\+?86)?` + // 匹配 0,86,+86
//	`(13[0-9]|` + // 130-139
//	`14[579]|` + // 145,147,149
//	`15[0-9]|` + // 150-153,155-159
//	`17[0135678]|` + // 170,171,173,175,176,177,178
//	`18[0-9]|` + // 180-189
//	`16[56]|` + // 165,1666
//	`19[189])` + // 191,198,199
//	`[0-9]{8}`
//IPv4  = `(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)`

//const (
//	// 匹配大陆电话
//	cnPhonePattern = `((\d{3,4})-?)?` + // 区号
//		`\d{5,10}` + // 号码，95500等5位数的，7位，8位，以及400开头的10位数
//		`(-\d{1,4})?` // 分机号，分机号的连接符号不能省略。
//
//	// 匹配大陆手机号码
//	cnMobilePattern = `(0|\+?86)?` + // 匹配 0,86,+86
//		`(13[0-9]|` + // 130-139
//		`14[579]|` + // 145,147,149
//		`15[0-9]|` + // 150-153,155-159
//		`17[0135678]|` + // 170,171,173,175,176,177,178
//		`18[0-9]|` + // 180-189
//		`16[56]|` + // 165,1666
//		`19[189])` + // 191,198,199
//		`[0-9]{8}`
//
//	// 匹配大陆手机号或是电话号码
//	cnTelPattern = "(" + cnPhonePattern + ")|(" + cnMobilePattern + ")"
//
//	// 匹配邮箱
//	emailPattern = `[\w.-]+@[\w_-]+\w{1,}[\.\w-]+`
//
//	// 匹配 IP4
//	ip4Pattern = `((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)`
//
//	// 匹配 IP6，参考以下网页内容：
//	// http://blog.csdn.net/jiangfeng08/article/details/7642018
//	ip6Pattern = `(([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|` +
//		`(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|` +
//		`(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|` +
//		`(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|` +
//		`(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|` +
//		`(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|` +
//		`(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|` +
//		`(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))`
//
//	// 同时匹配 IP4 和 IP6
//	ipPattern = "(" + ip4Pattern + ")|(" + ip6Pattern + ")"
//
//	// 匹配域名
//	domainPattern = `[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}(\.[a-zA-Z0-9][a-zA-Z0-9_-]{0,62})*(\.[a-zA-Z][a-zA-Z0-9]{0,10}){1}`
//
//	// 匹配 URL
//	urlPattern = `((https|http|ftp|rtsp|mms)?://)?` + // 协议
//		`(([0-9a-zA-Z]+:)?[0-9a-zA-Z_-]+@)?` + // pwd:user@
//		"(" + ipPattern + "|(" + domainPattern + "))" + // IPv4 或域名
//		`(:\d{1,5})?` + // 端口
//		`(/+[a-zA-Z0-9][a-zA-Z0-9_.-]*)*/*` + // path
//		`(\?([a-zA-Z0-9_-]+(=.*&?)*)*)*` // query
//)

//var (
//	email    = regexpCompile(emailPattern)
//	ip4      = regexpCompile(ip4Pattern)
//	ip6      = regexpCompile(ip6Pattern)
//	ip       = regexpCompile(ipPattern)
//	url      = regexpCompile(urlPattern)
//	cnPhone  = regexpCompile(cnPhonePattern)
//	cnMobile = regexpCompile(cnMobilePattern)
//	cnTel    = regexpCompile(cnTelPattern)
//)

//func regexpCompile(str string) *regexp.Regexp {
//	return regexp.MustCompile("^" + str + "$")
//}

// 判断val是否能正确匹配exp中的正则表达式。
// val可以是[]byte, []rune, string类型。
//func isMatch(exp *regexp.Regexp, val interface{}) bool {
//	switch v := val.(type) {
//	case []rune:
//		return exp.MatchString(string(v))
//	case []byte:
//		return exp.Match(v)
//	case string:
//		return exp.MatchString(v)
//	default:
//		return false
//	}
//}

//
//// CNPhone 验证中国大陆的电话号码。支持如下格式：
////  0578-12345678-1234
////  057812345678-1234
//// 若存在分机号，则分机号的连接符不能省略。
//func CNPhone(val interface{}) bool {
//	return isMatch(cnPhone, val)
//}
//
//// CNMobile 验证中国大陆的手机号码
//func CNMobile(val interface{}) bool {
//	return isMatch(cnMobile, val)
//}
//
//// CNTel 验证手机和电话类型
//func CNTel(val interface{}) bool {
//	return isMatch(cnTel, val)
//}
//
//// URL 验证一个值是否标准的URL格式。支持IP和域名等格式
//func URL(val interface{}) bool {
//	return isMatch(url, val)
//}
//
//// IPv4 验证一个值是否为IP，可验证IP4和IP6
//func IPv4(val interface{}) bool {
//	return isMatch(ip, val)
//}
//
//// IP6 验证一个值是否为IP6
//func IP6(val interface{}) bool {
//	return isMatch(ip6, val)
//}
//
//// IP4 验证一个值是滞为IP4
//func IP4(val interface{}) bool {
//	return isMatch(ip4, val)
//}
//
//// Email 验证一个值是否匹配一个邮箱。
//func Email(val interface{}) bool {
//	return isMatch(email, val)
//}
