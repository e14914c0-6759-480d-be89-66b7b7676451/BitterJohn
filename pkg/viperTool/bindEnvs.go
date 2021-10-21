package viperTool

import (
	"bytes"
	"fmt"
	"github.com/Masterminds/sprig"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/common"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/spf13/viper"
	"reflect"
	"strings"
	"text/template"
)

var (
	ErrRequired               = fmt.Errorf("required")
	ErrMutualReference        = fmt.Errorf("mutual reference or invalid value")
	ErrOverlayHierarchicalKey = fmt.Errorf("overlay hierarchical key")
)

type EnvBinder struct {
	viper     *viper.Viper
	toResolve map[string]string
	resolved  map[string]interface{}
}

func NewEnvBinder(viper *viper.Viper) *EnvBinder {
	return &EnvBinder{
		viper:     viper,
		toResolve: make(map[string]string),
		resolved:  make(map[string]interface{}),
	}
}

func (b *EnvBinder) Bind(iface interface{}) error {
	if err := b.bindEnvs(iface); err != nil {
		return err
	}
	for len(b.toResolve) > 0 {
		var changed bool
		for key, expr := range b.toResolve {
			ok, err := b.bindKey(key, expr)
			if err != nil {
				return err
			}
			if ok {
				changed = true
				if err := SetValueHierarchicalMap(b.resolved, key, b.viper.Get(key)); err != nil {
					return fmt.Errorf("%w: %v", err, key)
				}
				delete(b.toResolve, key)
			}
		}
		if !changed {
			return fmt.Errorf("%v: %w", strings.Join(common.MustMapKeys(b.toResolve), ", "), ErrMutualReference)
		}
	}
	return nil
}

func (b *EnvBinder) bindEnvs(iface interface{}, parts ...string) error {
	// https://github.com/spf13/viper/issues/188
	ifv := reflect.ValueOf(iface)
	ift := reflect.TypeOf(iface)
nextField:
	for i := 0; i < ift.NumField(); i++ {
		v := ifv.Field(i)
		t := ift.Field(i)
		tv, ok := t.Tag.Lookup("mapstructure")
		if !ok {
			continue
		}
		switch v.Kind() {
		case reflect.Struct:
			if err := b.bindEnvs(v.Interface(), append(parts, tv)...); err != nil {
				return err
			}
		default:
			key := strings.Join(append(parts, tv), ".")
			b.viper.BindEnv(key)
			if b.viper.Get(key) == nil {
				if tv, ok := t.Tag.Lookup("default"); ok {
					ok, err := b.bindKey(key, tv)
					if err != nil {
						return err
					}
					if !ok {
						b.toResolve[key] = tv
						continue nextField
					}
				} else if _, ok := t.Tag.Lookup("required"); ok {
					if desc, ok := t.Tag.Lookup("desc"); ok {
						key += " (" + desc + ")"
					}
					return fmt.Errorf("%w: %v", ErrRequired, key)
				}
			}
			if err := SetValueHierarchicalMap(b.resolved, key, b.viper.Get(key)); err != nil {
				return fmt.Errorf("%w: %v", err, key)
			}
		}
	}
	return nil
}

func (b *EnvBinder) bindKey(key string, expr string) (ok bool, err error) {
	//	support `mapstructure:"port" default:"{{with $arr := split \":\" .john.listen}}{{$arr._1}}{{end}}"`
	tmpl, err := template.New(key).Funcs(sprig.TxtFuncMap()).Parse(expr)
	if err != nil {
		return false, fmt.Errorf("failed to parse default value of key %v: %w", key, err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, b.resolved); err != nil {
		log.Warn("%v", err)
		if strings.Contains(err.Error(), "invalid value") {
			return false, nil
		}
		return false, fmt.Errorf("failed to parse default value of key %v: %w", key, err)
	}
	if strings.Contains(buf.String(), "<no value>") {
		log.Warn("%v", buf.String())
		return false, nil
	}
	b.viper.Set(key, buf.String())
	return true, nil
}

func SetValueHierarchicalMap(m map[string]interface{}, key string, val interface{}) error {
	keys := strings.Split(key, ".")
	lastKey := keys[len(keys)-1]
	keys = keys[:len(keys)-1]
	p := &m
	for _, key := range keys {
		if v, ok := (*p)[key]; ok {
			vv, ok := v.(map[string]interface{})
			if !ok {
				return ErrOverlayHierarchicalKey
			}
			p = &vv
		} else {
			(*p)[key] = make(map[string]interface{})
			vv := (*p)[key].(map[string]interface{})
			p = &vv
		}
	}
	(*p)[lastKey] = val
	return nil
}
