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

package masker

import (
	"fmt"
	"github.com/normal-coder/go-masker/util/regRule"
	"reflect"
	"regexp"
	"strings"
)

var funcs = map[string]interface{}{
	"FindEmail": FindEmail,
	"FindIPv4":  FindIPv4,
	"FindPhone": FindPhone,
	"MaskEmail": MaskEmail,
	"MaskIPv4":  MaskIPv4,
	"MaskPhone": MaskPhone,
}

var maxMatchCount = 10

func hasMatch(input string, RegRule string) bool {
	match, _ := regexp.MatchString(RegRule, input)
	return match
}

func Call(method map[string]interface{}, name string, params ...interface{}) (result []reflect.Value, err error) {
	f := reflect.ValueOf(method[name])
	inParam := make([]reflect.Value, len(params))
	for k, param := range params {
		inParam[k] = reflect.ValueOf(param)
	}
	result = f.Call(inParam)
	return
}

func MaskString(input string, start int) string {
	if len(input) <= start {
		return input
	}
	lenStart := len(input[start:])
	switch {
	case lenStart <= 3:
		return input[:start] + strings.Repeat("*", lenStart)
	case 3 < lenStart && lenStart <= 5:
		fmt.Println(input)
		return input[:start+1] + strings.Repeat("*", lenStart-2) + input[lenStart+start-1:]
	case 5 < lenStart && lenStart <= 10:
		return input[:start+2] + strings.Repeat("*", lenStart-4) + input[lenStart+start-2:]
	case lenStart > 10:
		return input[:start+4] + strings.Repeat("*", lenStart-8) + input[lenStart+start-4:]
	default:
		return ""
	}
}

func MaskAll(input string) string {
	result := input
	for i, v := range regRule.All {
		if hasMatch(result, v) {
			if maskResult, err := Call(funcs, "Mask"+i, result); err == nil {
				result = maskResult[0].String()
			}
		}
	}
	return result
}

func FindPhone(input string) [][]string {
	return regexp.MustCompile(regRule.Phone).FindAllStringSubmatch(input, maxMatchCount)
}

func MaskPhone(input string) string {
	targets := FindPhone(input)
	for _, target := range targets {
		maskedTarget := target[0][:3] + "****" + target[0][len(target[0])-4:]
		input = strings.Replace(input, target[0], maskedTarget, -1)
	}
	return input

}

func FindIPv4(input string) [][]string {
	return regexp.MustCompile(regRule.IPv4).FindAllStringSubmatch(input, maxMatchCount)
}

func MaskIPv4(input string) string {
	targets := FindIPv4(input)
	for _, target := range targets {
		maskedTarget := target[1] + "." + MaskString(target[2], 0) + "." + MaskString(target[3], 0) + "." + target[4]
		input = strings.Replace(input, target[0], maskedTarget, -1)
	}
	return input
}

func FindEmail(input string) [][]string {
	return regexp.MustCompile(regRule.Email).FindAllStringSubmatch(input, maxMatchCount)
}

func MaskEmail(input string) string {
	targets := FindEmail(input)
	for _, target := range targets {
		maskedTarget := MaskString(target[1], 0) + "@" + MaskString(target[2], 0) + MaskString(target[3], 1)
		input = strings.Replace(input, target[0], maskedTarget, -1)
	}
	return input
}
