package model

import "testing"

func TestSubsetOf(t *testing.T) {
	cases := []struct {
		sel, labels []string
		want        bool
	}{
		{nil, []string{"机房A"}, true},                      // 空选择器任意命中
		{[]string{}, []string{"机房A"}, true},               // 同上
		{[]string{"机房A"}, []string{"机房A", "核心"}, true}, // 子集命中
		{[]string{"机房A", "核心"}, []string{"机房A", "核心"}, true},
		{[]string{"机房B"}, []string{"机房A", "核心"}, false}, // 不命中
		{[]string{"机房A"}, nil, false},                      // 探针无标签，非空选择器不命中
	}
	for _, c := range cases {
		if got := SubsetOf(c.sel, c.labels); got != c.want {
			t.Errorf("SubsetOf(%v,%v)=%v want %v", c.sel, c.labels, got, c.want)
		}
	}
}
