package govaluate

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"strings"
)

const (
	logicalErrorFormat    string = "Value '%v' cannot be used with the logical operator '%v', it is not a bool"
	modifierErrorFormat   string = "Value '%v' cannot be used with the modifier '%v', it is not a number"
	comparatorErrorFormat string = "Value '%v' cannot be used with the comparator '%v', it is not a number"
	ternaryErrorFormat    string = "Value '%v' cannot be used with the ternary operator '%v', it is not a bool"
	prefixErrorFormat     string = "Value '%v' cannot be used with the prefix '%v'"
)

type Operator func(left interface{}, right interface{}, parameters Parameters) (interface{}, error)
type OperatorOverloads struct {
	Type  reflect.Type
	Sub   Operator
	Add   Operator
	Mul   Operator
	Div   Operator
	Exp   Operator
	Mod   Operator
	Gte   Operator
	Gt    Operator
	Lte   Operator
	Lt    Operator
	Eq    Operator
	NEq   Operator
	And   Operator
	Or    Operator
	Neg   Operator
	Tif   Operator
	Telse Operator
	Inv   Operator
	BNot  Operator
	BOr   Operator
	BAnd  Operator
	BXor  Operator
	LShft Operator
	RShft Operator
	Reg   Operator
	NReg  Operator
	In    Operator
	Sep   Operator
}
type OperatorOverloadMap map[reflect.Type]OperatorOverloads

type evaluationOperator func(ops *OperatorOverloadMap, left interface{}, right interface{}, parameters Parameters) (interface{}, error)
type stageTypeCheck func(value interface{}) bool
type stageCombinedTypeCheck func(left interface{}, right interface{}) bool

type evaluationStage struct {
	symbol OperatorSymbol

	leftStage, rightStage *evaluationStage

	// the operation that will be used to evaluate this stage (such as adding [left] to [right] and return the result)
	operator evaluationOperator

	// ensures that both left and right values are appropriate for this stage. Returns an error if they aren't operable.
	leftTypeCheck  stageTypeCheck
	rightTypeCheck stageTypeCheck

	// if specified, will override whatever is used in "leftTypeCheck" and "rightTypeCheck".
	// primarily used for specific operators that don't care which side a given type is on, but still requires one side to be of a given type
	// (like string concat)
	typeCheck stageCombinedTypeCheck

	// regardless of which type check is used, this string format will be used as the error message for type errors
	typeErrorFormat string
}

var (
	_true  = interface{}(true)
	_false = interface{}(false)
)

func (this *evaluationStage) swapWith(other *evaluationStage) {

	temp := *other
	other.setToNonStage(*this)
	this.setToNonStage(temp)
}

func (this *evaluationStage) setToNonStage(other evaluationStage) {

	this.symbol = other.symbol
	this.operator = other.operator
	this.leftTypeCheck = other.leftTypeCheck
	this.rightTypeCheck = other.rightTypeCheck
	this.typeCheck = other.typeCheck
	this.typeErrorFormat = other.typeErrorFormat
}

func (this *evaluationStage) isShortCircuitable() bool {

	switch this.symbol {
	case AND:
		fallthrough
	case OR:
		fallthrough
	case TERNARY_TRUE:
		fallthrough
	case TERNARY_FALSE:
		fallthrough
	case COALESCE:
		return true
	}

	return false
}

func noopStageRight(ops *OperatorOverloadMap, left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	return right, nil
}

func addStage(ops *OperatorOverloadMap, left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if ops != nil {
		if ovl, ok := (*ops)[reflect.TypeOf(left)]; ok && ovl.Add != nil {
			return ovl.Add(left, right, parameters)
		} else if ovl, ok := (*ops)[reflect.TypeOf(right)]; ok && ovl.Add != nil {
			return ovl.Add(left, right, parameters)
		}
	}
	// string concat if either are strings
	if isString(left) || isString(right) {
		return fmt.Sprintf("%v%v", left, right), nil
	}

	return left.(float64) + right.(float64), nil
}

func subtractStage(ops *OperatorOverloadMap, left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if ops != nil {
		if ovl, ok := (*ops)[reflect.TypeOf(left)]; ok && ovl.Sub != nil {
			return ovl.Sub(left, right, parameters)
		} else if ovl, ok := (*ops)[reflect.TypeOf(right)]; ok && ovl.Sub != nil {
			return ovl.Sub(left, right, parameters)
		}
	}
	return left.(float64) - right.(float64), nil
}
func multiplyStage(ops *OperatorOverloadMap, left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if ops != nil {
		if ovl, ok := (*ops)[reflect.TypeOf(left)]; ok && ovl.Mul != nil {
			return ovl.Mul(left, right, parameters)
		} else if ovl, ok := (*ops)[reflect.TypeOf(right)]; ok && ovl.Mul != nil {
			return ovl.Mul(left, right, parameters)
		}
	}
	return left.(float64) * right.(float64), nil
}
func divideStage(ops *OperatorOverloadMap, left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if ops != nil {
		if ovl, ok := (*ops)[reflect.TypeOf(left)]; ok && ovl.Div != nil {
			return ovl.Div(left, right, parameters)
		} else if ovl, ok := (*ops)[reflect.TypeOf(right)]; ok && ovl.Div != nil {
			return ovl.Div(left, right, parameters)
		}
	}
	return left.(float64) / right.(float64), nil
}
func exponentStage(ops *OperatorOverloadMap, left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if ops != nil {
		if ovl, ok := (*ops)[reflect.TypeOf(left)]; ok && ovl.Exp != nil {
			return ovl.Exp(left, right, parameters)
		} else if ovl, ok := (*ops)[reflect.TypeOf(right)]; ok && ovl.Exp != nil {
			return ovl.Exp(left, right, parameters)
		}
	}
	return math.Pow(left.(float64), right.(float64)), nil
}
func modulusStage(ops *OperatorOverloadMap, left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if ops != nil {
		if ovl, ok := (*ops)[reflect.TypeOf(left)]; ok && ovl.Mod != nil {
			return ovl.Mod(left, right, parameters)
		} else if ovl, ok := (*ops)[reflect.TypeOf(right)]; ok && ovl.Mod != nil {
			return ovl.Mod(left, right, parameters)
		}
	}
	return math.Mod(left.(float64), right.(float64)), nil
}
func gteStage(ops *OperatorOverloadMap, left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if ops != nil {
		if ovl, ok := (*ops)[reflect.TypeOf(left)]; ok && ovl.Gte != nil {
			return ovl.Gte(left, right, parameters)
		} else if ovl, ok := (*ops)[reflect.TypeOf(right)]; ok && ovl.Gte != nil {
			return ovl.Gte(left, right, parameters)
		}
	}
	if isString(left) && isString(right) {
		return boolIface(left.(string) >= right.(string)), nil
	}
	return boolIface(left.(float64) >= right.(float64)), nil
}
func gtStage(ops *OperatorOverloadMap, left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if ops != nil {
		if ovl, ok := (*ops)[reflect.TypeOf(left)]; ok && ovl.Gt != nil {
			return ovl.Gt(left, right, parameters)
		} else if ovl, ok := (*ops)[reflect.TypeOf(right)]; ok && ovl.Gt != nil {
			return ovl.Gt(left, right, parameters)
		}
	}
	if isString(left) && isString(right) {
		return boolIface(left.(string) > right.(string)), nil
	}
	return boolIface(left.(float64) > right.(float64)), nil
}
func lteStage(ops *OperatorOverloadMap, left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if ops != nil {
		if ovl, ok := (*ops)[reflect.TypeOf(left)]; ok && ovl.Lte != nil {
			return ovl.Lte(left, right, parameters)
		} else if ovl, ok := (*ops)[reflect.TypeOf(right)]; ok && ovl.Lte != nil {
			return ovl.Lte(left, right, parameters)
		}
	}
	if isString(left) && isString(right) {
		return boolIface(left.(string) <= right.(string)), nil
	}
	return boolIface(left.(float64) <= right.(float64)), nil
}
func ltStage(ops *OperatorOverloadMap, left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if ops != nil {
		if ovl, ok := (*ops)[reflect.TypeOf(left)]; ok && ovl.Lt != nil {
			return ovl.Lt(left, right, parameters)
		} else if ovl, ok := (*ops)[reflect.TypeOf(right)]; ok && ovl.Lt != nil {
			return ovl.Lt(left, right, parameters)
		}
	}
	if isString(left) && isString(right) {
		return boolIface(left.(string) < right.(string)), nil
	}
	return boolIface(left.(float64) < right.(float64)), nil
}
func equalStage(ops *OperatorOverloadMap, left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if ops != nil {
		if ovl, ok := (*ops)[reflect.TypeOf(left)]; ok && ovl.Eq != nil {
			return ovl.Eq(left, right, parameters)
		} else if ovl, ok := (*ops)[reflect.TypeOf(right)]; ok && ovl.Eq != nil {
			return ovl.Eq(left, right, parameters)
		}
	}
	return boolIface(reflect.DeepEqual(left, right)), nil
}
func notEqualStage(ops *OperatorOverloadMap, left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if ops != nil {
		if ovl, ok := (*ops)[reflect.TypeOf(left)]; ok && ovl.NEq != nil {
			return ovl.NEq(left, right, parameters)
		} else if ovl, ok := (*ops)[reflect.TypeOf(right)]; ok && ovl.NEq != nil {
			return ovl.NEq(left, right, parameters)
		}
	}
	return boolIface(!reflect.DeepEqual(left, right)), nil
}
func andStage(ops *OperatorOverloadMap, left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if ops != nil {
		if ovl, ok := (*ops)[reflect.TypeOf(left)]; ok && ovl.And != nil {
			return ovl.And(left, right, parameters)
		} else if ovl, ok := (*ops)[reflect.TypeOf(right)]; ok && ovl.And != nil {
			return ovl.And(left, right, parameters)
		}
	}
	return boolIface(left.(bool) && right.(bool)), nil
}
func orStage(ops *OperatorOverloadMap, left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if ops != nil {
		if ovl, ok := (*ops)[reflect.TypeOf(left)]; ok && ovl.Or != nil {
			return ovl.Or(left, right, parameters)
		} else if ovl, ok := (*ops)[reflect.TypeOf(right)]; ok && ovl.Or != nil {
			return ovl.Or(left, right, parameters)
		}
	}
	return boolIface(left.(bool) || right.(bool)), nil
}
func negateStage(ops *OperatorOverloadMap, left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if ops != nil {
		if ovl, ok := (*ops)[reflect.TypeOf(left)]; ok && ovl.Neg != nil {
			return ovl.Neg(left, right, parameters)
		} else if ovl, ok := (*ops)[reflect.TypeOf(right)]; ok && ovl.Neg != nil {
			return ovl.Neg(left, right, parameters)
		}
	}
	return -right.(float64), nil
}
func invertStage(ops *OperatorOverloadMap, left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if ops != nil {
		if ovl, ok := (*ops)[reflect.TypeOf(left)]; ok && ovl.Inv != nil {
			return ovl.Inv(left, right, parameters)
		} else if ovl, ok := (*ops)[reflect.TypeOf(right)]; ok && ovl.Inv != nil {
			return ovl.Inv(left, right, parameters)
		}
	}
	return boolIface(!right.(bool)), nil
}
func bitwiseNotStage(ops *OperatorOverloadMap, left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if ops != nil {
		if ovl, ok := (*ops)[reflect.TypeOf(left)]; ok && ovl.BNot != nil {
			return ovl.BNot(left, right, parameters)
		} else if ovl, ok := (*ops)[reflect.TypeOf(right)]; ok && ovl.BNot != nil {
			return ovl.BNot(left, right, parameters)
		}
	}
	return float64(^int64(right.(float64))), nil
}
func ternaryIfStage(ops *OperatorOverloadMap, left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if ops != nil {
		if ovl, ok := (*ops)[reflect.TypeOf(left)]; ok && ovl.Tif != nil {
			return ovl.Tif(left, right, parameters)
		} else if ovl, ok := (*ops)[reflect.TypeOf(right)]; ok && ovl.Tif != nil {
			return ovl.Tif(left, right, parameters)
		}
	}
	if left.(bool) {
		return right, nil
	}
	return nil, nil
}
func ternaryElseStage(ops *OperatorOverloadMap, left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if ops != nil {
		if ovl, ok := (*ops)[reflect.TypeOf(left)]; ok && ovl.Telse != nil {
			return ovl.Telse(left, right, parameters)
		} else if ovl, ok := (*ops)[reflect.TypeOf(right)]; ok && ovl.Telse != nil {
			return ovl.Telse(left, right, parameters)
		}
	}
	if left != nil {
		return left, nil
	}
	return right, nil
}

func regexStage(ops *OperatorOverloadMap, left interface{}, right interface{}, parameters Parameters) (interface{}, error) {

	if ops != nil {
		if ovl, ok := (*ops)[reflect.TypeOf(left)]; ok && ovl.Reg != nil {
			return ovl.Reg(left, right, parameters)
		} else if ovl, ok := (*ops)[reflect.TypeOf(right)]; ok && ovl.Reg != nil {
			return ovl.Reg(left, right, parameters)
		}
	}
	var pattern *regexp.Regexp
	var err error

	switch right.(type) {
	case string:
		pattern, err = regexp.Compile(right.(string))
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Unable to compile regexp pattern '%v': %v", right, err))
		}
	case *regexp.Regexp:
		pattern = right.(*regexp.Regexp)
	}

	return pattern.Match([]byte(left.(string))), nil
}

func notRegexStage(ops *OperatorOverloadMap, left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if ops != nil {
		if ovl, ok := (*ops)[reflect.TypeOf(left)]; ok && ovl.NReg != nil {
			return ovl.NReg(left, right, parameters)
		} else if ovl, ok := (*ops)[reflect.TypeOf(right)]; ok && ovl.NReg != nil {
			return ovl.NReg(left, right, parameters)
		}
	}

	ret, err := regexStage(ops, left, right, parameters)
	if err != nil {
		return nil, err
	}

	return !(ret.(bool)), nil
}

func bitwiseOrStage(ops *OperatorOverloadMap, left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if ops != nil {
		if ovl, ok := (*ops)[reflect.TypeOf(left)]; ok && ovl.BOr != nil {
			return ovl.BOr(left, right, parameters)
		} else if ovl, ok := (*ops)[reflect.TypeOf(right)]; ok && ovl.BOr != nil {
			return ovl.BOr(left, right, parameters)
		}
	}
	return float64(int64(left.(float64)) | int64(right.(float64))), nil
}
func bitwiseAndStage(ops *OperatorOverloadMap, left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if ops != nil {
		if ovl, ok := (*ops)[reflect.TypeOf(left)]; ok && ovl.BAnd != nil {
			return ovl.BAnd(left, right, parameters)
		} else if ovl, ok := (*ops)[reflect.TypeOf(right)]; ok && ovl.BAnd != nil {
			return ovl.BAnd(left, right, parameters)
		}
	}
	return float64(int64(left.(float64)) & int64(right.(float64))), nil
}
func bitwiseXORStage(ops *OperatorOverloadMap, left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if ops != nil {
		if ovl, ok := (*ops)[reflect.TypeOf(left)]; ok && ovl.BXor != nil {
			return ovl.BXor(left, right, parameters)
		} else if ovl, ok := (*ops)[reflect.TypeOf(right)]; ok && ovl.BXor != nil {
			return ovl.BXor(left, right, parameters)
		}
	}
	return float64(int64(left.(float64)) ^ int64(right.(float64))), nil
}
func leftShiftStage(ops *OperatorOverloadMap, left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if ops != nil {
		if ovl, ok := (*ops)[reflect.TypeOf(left)]; ok && ovl.LShft != nil {
			return ovl.LShft(left, right, parameters)
		} else if ovl, ok := (*ops)[reflect.TypeOf(right)]; ok && ovl.LShft != nil {
			return ovl.LShft(left, right, parameters)
		}
	}
	return float64(uint64(left.(float64)) << uint64(right.(float64))), nil
}
func rightShiftStage(ops *OperatorOverloadMap, left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if ops != nil {
		if ovl, ok := (*ops)[reflect.TypeOf(left)]; ok && ovl.RShft != nil {
			return ovl.RShft(left, right, parameters)
		} else if ovl, ok := (*ops)[reflect.TypeOf(right)]; ok && ovl.RShft != nil {
			return ovl.RShft(left, right, parameters)
		}
	}
	return float64(uint64(left.(float64)) >> uint64(right.(float64))), nil
}

func makeParameterStage(parameterName string) evaluationOperator {

	return func(ops *OperatorOverloadMap, left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
		value, err := parameters.Get(parameterName)
		if err != nil {
			return nil, err
		}

		return value, nil
	}
}

func makeLiteralStage(literal interface{}) evaluationOperator {
	return func(ops *OperatorOverloadMap, left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
		return literal, nil
	}
}

func makeFunctionStage(function ExpressionFunction) evaluationOperator {

	return func(ops *OperatorOverloadMap, left interface{}, right interface{}, parameters Parameters) (interface{}, error) {

		if right == nil {
			return function()
		}

		switch right.(type) {
		case []interface{}:
			return function(right.([]interface{})...)
		default:
			return function(right)
		}
	}
}

func typeConvertParam(p reflect.Value, t reflect.Type) (ret reflect.Value, err error) {
	defer func() {
		if r := recover(); r != nil {
			errorMsg := fmt.Sprintf("Argument type conversion failed: failed to convert '%s' to '%s'", p.Kind().String(), t.Kind().String())
			err = errors.New(errorMsg)
			ret = p
		}
	}()

	return p.Convert(t), nil
}

func typeConvertParams(method reflect.Value, params []reflect.Value) ([]reflect.Value, error) {

	methodType := method.Type()
	numIn := methodType.NumIn()
	numParams := len(params)

	if numIn != numParams {
		if numIn > numParams {
			return nil, fmt.Errorf("Too few arguments to parameter call: got %d arguments, expected %d", len(params), numIn)
		}
		return nil, fmt.Errorf("Too many arguments to parameter call: got %d arguments, expected %d", len(params), numIn)
	}

	for i := 0; i < numIn; i++ {
		t := methodType.In(i)
		p := params[i]
		pt := p.Type()

		if t.Kind() != pt.Kind() {
			np, err := typeConvertParam(p, t)
			if err != nil {
				return nil, err
			}
			params[i] = np
		}
	}

	return params, nil
}

func makeAccessorStage(pair []string) evaluationOperator {

	reconstructed := strings.Join(pair, ".")

	return func(ops *OperatorOverloadMap, left interface{}, right interface{}, parameters Parameters) (ret interface{}, err error) {

		var params []reflect.Value

		value, err := parameters.Get(pair[0])
		if err != nil {
			return nil, err
		}

		// while this library generally tries to handle panic-inducing cases on its own,
		// accessors are a sticky case which have a lot of possible ways to fail.
		// therefore every call to an accessor sets up a defer that tries to recover from panics, converting them to errors.
		defer func() {
			if r := recover(); r != nil {
				errorMsg := fmt.Sprintf("Failed to access '%s': %v", reconstructed, r.(string))
				err = errors.New(errorMsg)
				ret = nil
			}
		}()

		for i := 1; i < len(pair); i++ {

			coreValue := reflect.ValueOf(value)

			var corePtrVal reflect.Value

			// if this is a pointer, resolve it.
			if coreValue.Kind() == reflect.Ptr {
				corePtrVal = coreValue
				coreValue = coreValue.Elem()
			}

			if coreValue.Kind() != reflect.Struct {
				return nil, errors.New("Unable to access '" + pair[i] + "', '" + pair[i-1] + "' is not a struct")
			}

			field := coreValue.FieldByName(pair[i])
			if field != (reflect.Value{}) {
				value = field.Interface()
				continue
			}

			method := coreValue.MethodByName(pair[i])
			if method == (reflect.Value{}) {
				if corePtrVal.IsValid() {
					method = corePtrVal.MethodByName(pair[i])
				}
				if method == (reflect.Value{}) {
					return nil, errors.New("No method or field '" + pair[i] + "' present on parameter '" + pair[i-1] + "'")
				}
			}

			switch right.(type) {
			case []interface{}:

				givenParams := right.([]interface{})
				params = make([]reflect.Value, len(givenParams))
				for idx, _ := range givenParams {
					params[idx] = reflect.ValueOf(givenParams[idx])
				}

			default:

				if right == nil {
					params = []reflect.Value{}
					break
				}

				params = []reflect.Value{reflect.ValueOf(right.(interface{}))}
			}

			params, err = typeConvertParams(method, params)

			if err != nil {
				return nil, errors.New("Method call failed - '" + pair[0] + "." + pair[1] + "': " + err.Error())
			}

			returned := method.Call(params)
			retLength := len(returned)

			if retLength == 0 {
				return nil, errors.New("Method call '" + pair[i-1] + "." + pair[i] + "' did not return any values.")
			}

			if retLength == 1 {

				value = returned[0].Interface()
				continue
			}

			if retLength == 2 {

				errIface := returned[1].Interface()
				err, validType := errIface.(error)

				if validType && errIface != nil {
					return returned[0].Interface(), err
				}

				value = returned[0].Interface()
				continue
			}

			return nil, errors.New("Method call '" + pair[0] + "." + pair[1] + "' did not return either one value, or a value and an error. Cannot interpret meaning.")
		}

		value = castToFloat64(value)
		return value, nil
	}
}

func separatorStage(ops *OperatorOverloadMap, left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if ops != nil {
		if ovl, ok := (*ops)[reflect.TypeOf(left)]; ok && ovl.Sep != nil {
			return ovl.Sep(left, right, parameters)
		} else if ovl, ok := (*ops)[reflect.TypeOf(right)]; ok && ovl.Sep != nil {
			return ovl.Sep(left, right, parameters)
		}
	}
	var ret []interface{}

	switch left.(type) {
	case []interface{}:
		ret = append(left.([]interface{}), right)
	default:
		ret = []interface{}{left, right}
	}

	return ret, nil
}

func inStage(ops *OperatorOverloadMap, left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if ops != nil {
		if ovl, ok := (*ops)[reflect.TypeOf(left)]; ok && ovl.In != nil {
			return ovl.In(left, right, parameters)
		} else if ovl, ok := (*ops)[reflect.TypeOf(right)]; ok && ovl.In != nil {
			return ovl.In(left, right, parameters)
		}
	}
	for _, value := range right.([]interface{}) {
		if left == value {
			return true, nil
		}
	}
	return false, nil
}

//

func isString(value interface{}) bool {

	switch value.(type) {
	case string:
		return true
	}
	return false
}

func isRegexOrString(value interface{}) bool {

	switch value.(type) {
	case string:
		return true
	case *regexp.Regexp:
		return true
	}
	return false
}

func isBool(value interface{}) bool {
	switch value.(type) {
	case bool:
		return true
	}
	return false
}

func isFloat64(value interface{}) bool {
	switch value.(type) {
	case float64:
		return true
	}
	return false
}

/*
Addition usually means between numbers, but can also mean string concat.
String concat needs one (or both) of the sides to be a string.
*/
func additionTypeCheck(left interface{}, right interface{}) bool {

	if isFloat64(left) && isFloat64(right) {
		return true
	}
	if !isString(left) && !isString(right) {
		return false
	}
	return true
}

/*
Comparison can either be between numbers, or lexicographic between two strings,
but never between the two.
*/
func comparatorTypeCheck(left interface{}, right interface{}) bool {

	if isFloat64(left) && isFloat64(right) {
		return true
	}
	if isString(left) && isString(right) {
		return true
	}
	return false
}

func isArray(value interface{}) bool {
	switch value.(type) {
	case []interface{}:
		return true
	}
	return false
}

/*
Converting a boolean to an interface{} requires an allocation.
We can use interned bools to avoid this cost.
*/
func boolIface(b bool) interface{} {
	if b {
		return _true
	}
	return _false
}
