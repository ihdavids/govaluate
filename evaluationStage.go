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

type evaluationOperator func(left interface{}, right interface{}, parameters Parameters) (interface{}, error)
type stageTypeCheck func(value interface{}) bool
type stageCombinedTypeCheck func(left interface{}, right interface{}) bool

type Operator func(left interface{}, right interface{}, parameters Parameters) (interface{}, error)
type OpAdd interface {
	OpAdd(left interface{}, right interface{}, parameters Parameters) (interface{}, error)
}
type OpSub interface {
	OpSub(left interface{}, right interface{}, parameters Parameters) (interface{}, error)
}
type OpMul interface {
	OpMul(left interface{}, right interface{}, parameters Parameters) (interface{}, error)
}
type OpDiv interface {
	OpDiv(left interface{}, right interface{}, parameters Parameters) (interface{}, error)
}
type OpPow interface {
	OpPow(left interface{}, right interface{}, parameters Parameters) (interface{}, error)
}
type OpMod interface {
	OpMod(left interface{}, right interface{}, parameters Parameters) (interface{}, error)
}
type OpGte interface {
	OpGte(left interface{}, right interface{}, parameters Parameters) (interface{}, error)
}
type OpGt interface {
	OpGt(left interface{}, right interface{}, parameters Parameters) (interface{}, error)
}
type OpLte interface {
	OpLte(left interface{}, right interface{}, parameters Parameters) (interface{}, error)
}
type OpLt interface {
	OpLt(left interface{}, right interface{}, parameters Parameters) (interface{}, error)
}
type OpEq interface {
	OpEq(left interface{}, right interface{}, parameters Parameters) (interface{}, error)
}
type OpNEq interface {
	OpNEq(left interface{}, right interface{}, parameters Parameters) (interface{}, error)
}
type OpAnd interface {
	OpAnd(left interface{}, right interface{}, parameters Parameters) (interface{}, error)
}
type OpOr interface {
	OpOr(left interface{}, right interface{}, parameters Parameters) (interface{}, error)
}
type OpNeg interface {
	OpNeg(left interface{}, right interface{}, parameters Parameters) (interface{}, error)
}
type OpTif interface {
	OpTif(left interface{}, right interface{}, parameters Parameters) (interface{}, error)
}
type OpTelse interface {
	OpTelse(left interface{}, right interface{}, parameters Parameters) (interface{}, error)
}
type OpInv interface {
	OpInv(left interface{}, right interface{}, parameters Parameters) (interface{}, error)
}
type OpBNot interface {
	OpBNot(left interface{}, right interface{}, parameters Parameters) (interface{}, error)
}
type OpBOr interface {
	OpBOr(left interface{}, right interface{}, parameters Parameters) (interface{}, error)
}
type OpBAnd interface {
	OpBAnd(left interface{}, right interface{}, parameters Parameters) (interface{}, error)
}
type OpBXor interface {
	OpBXor(left interface{}, right interface{}, parameters Parameters) (interface{}, error)
}
type OpLShft interface {
	OpLShft(left interface{}, right interface{}, parameters Parameters) (interface{}, error)
}
type OpRShft interface {
	OpRShft(left interface{}, right interface{}, parameters Parameters) (interface{}, error)
}
type OpReg interface {
	OpReg(left interface{}, right interface{}, parameters Parameters) (interface{}, error)
}
type OpNReg interface {
	OpNReg(left interface{}, right interface{}, parameters Parameters) (interface{}, error)
}
type OpIn interface {
	OpIn(left interface{}, right interface{}, parameters Parameters) (interface{}, error)
}
type OpSep interface {
	OpSep(left interface{}, right interface{}, parameters Parameters) (interface{}, error)
}
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

func noopStageRight(left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	return right, nil
}

func addStage(left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if op, ok := left.(OpAdd); ok {
		return op.OpAdd(left, right, parameters)
	}
	if op, ok := right.(OpAdd); ok {
		return op.OpAdd(left, right, parameters)
	}
	// string concat if either are strings
	if isString(left) || isString(right) {
		return fmt.Sprintf("%v%v", left, right), nil
	}

	return left.(float64) + right.(float64), nil
}
func subtractStage(left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if op, ok := left.(OpSub); ok {
		return op.OpSub(left, right, parameters)
	}
	if op, ok := right.(OpSub); ok {
		return op.OpSub(left, right, parameters)
	}
	return left.(float64) - right.(float64), nil
}
func multiplyStage(left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if op, ok := left.(OpMul); ok {
		return op.OpMul(left, right, parameters)
	}
	if op, ok := right.(OpMul); ok {
		return op.OpMul(left, right, parameters)
	}
	return left.(float64) * right.(float64), nil
}
func divideStage(left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if op, ok := left.(OpDiv); ok {
		return op.OpDiv(left, right, parameters)
	}
	if op, ok := right.(OpDiv); ok {
		return op.OpDiv(left, right, parameters)
	}
	return left.(float64) / right.(float64), nil
}
func exponentStage(left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if op, ok := left.(OpPow); ok {
		return op.OpPow(left, right, parameters)
	}
	if op, ok := right.(OpPow); ok {
		return op.OpPow(left, right, parameters)
	}
	return math.Pow(left.(float64), right.(float64)), nil
}
func modulusStage(left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if op, ok := left.(OpMod); ok {
		return op.OpMod(left, right, parameters)
	}
	if op, ok := right.(OpMod); ok {
		return op.OpMod(left, right, parameters)
	}
	return math.Mod(left.(float64), right.(float64)), nil
}
func gteStage(left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if op, ok := left.(OpGte); ok {
		return op.OpGte(left, right, parameters)
	}
	if op, ok := right.(OpGte); ok {
		return op.OpGte(left, right, parameters)
	}
	if isString(left) && isString(right) {
		return boolIface(left.(string) >= right.(string)), nil
	}
	return boolIface(left.(float64) >= right.(float64)), nil
}
func gtStage(left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if op, ok := left.(OpGt); ok {
		return op.OpGt(left, right, parameters)
	}
	if op, ok := right.(OpGt); ok {
		return op.OpGt(left, right, parameters)
	}
	if isString(left) && isString(right) {
		return boolIface(left.(string) > right.(string)), nil
	}
	return boolIface(left.(float64) > right.(float64)), nil
}
func lteStage(left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if op, ok := left.(OpLte); ok {
		return op.OpLte(left, right, parameters)
	}
	if op, ok := right.(OpLte); ok {
		return op.OpLte(left, right, parameters)
	}
	if isString(left) && isString(right) {
		return boolIface(left.(string) <= right.(string)), nil
	}
	return boolIface(left.(float64) <= right.(float64)), nil
}
func ltStage(left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if op, ok := left.(OpLt); ok {
		return op.OpLt(left, right, parameters)
	}
	if op, ok := right.(OpLt); ok {
		return op.OpLt(left, right, parameters)
	}
	if isString(left) && isString(right) {
		return boolIface(left.(string) < right.(string)), nil
	}
	return boolIface(left.(float64) < right.(float64)), nil
}
func equalStage(left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if op, ok := left.(OpEq); ok {
		return op.OpEq(left, right, parameters)
	}
	if op, ok := right.(OpEq); ok {
		return op.OpEq(left, right, parameters)
	}
	return boolIface(reflect.DeepEqual(left, right)), nil
}
func notEqualStage(left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if op, ok := left.(OpNEq); ok {
		return op.OpNEq(left, right, parameters)
	}
	if op, ok := right.(OpNEq); ok {
		return op.OpNEq(left, right, parameters)
	}
	return boolIface(!reflect.DeepEqual(left, right)), nil
}
func andStage(left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if op, ok := left.(OpAnd); ok {
		return op.OpAnd(left, right, parameters)
	}
	if op, ok := right.(OpAnd); ok {
		return op.OpAnd(left, right, parameters)
	}
	return boolIface(left.(bool) && right.(bool)), nil
}
func orStage(left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if op, ok := left.(OpOr); ok {
		return op.OpOr(left, right, parameters)
	}
	if op, ok := right.(OpOr); ok {
		return op.OpOr(left, right, parameters)
	}
	return boolIface(left.(bool) || right.(bool)), nil
}
func negateStage(left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if op, ok := left.(OpNeg); ok {
		return op.OpNeg(left, right, parameters)
	}
	if op, ok := right.(OpNeg); ok {
		return op.OpNeg(left, right, parameters)
	}
	return -right.(float64), nil
}
func invertStage(left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if op, ok := left.(OpInv); ok {
		return op.OpInv(left, right, parameters)
	}
	if op, ok := right.(OpInv); ok {
		return op.OpInv(left, right, parameters)
	}
	return boolIface(!right.(bool)), nil
}
func bitwiseNotStage(left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if op, ok := left.(OpBNot); ok {
		return op.OpBNot(left, right, parameters)
	}
	if op, ok := right.(OpBNot); ok {
		return op.OpBNot(left, right, parameters)
	}
	return float64(^int64(right.(float64))), nil
}
func ternaryIfStage(left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if op, ok := left.(OpTif); ok {
		return op.OpTif(left, right, parameters)
	}
	if op, ok := right.(OpTif); ok {
		return op.OpTif(left, right, parameters)
	}
	if left.(bool) {
		return right, nil
	}
	return nil, nil
}
func ternaryElseStage(left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if op, ok := left.(OpTelse); ok {
		return op.OpTelse(left, right, parameters)
	}
	if op, ok := right.(OpTelse); ok {
		return op.OpTelse(left, right, parameters)
	}
	if left != nil {
		return left, nil
	}
	return right, nil
}

func regexStage(left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if op, ok := left.(OpReg); ok {
		return op.OpReg(left, right, parameters)
	}
	if op, ok := right.(OpReg); ok {
		return op.OpReg(left, right, parameters)
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

func notRegexStage(left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if op, ok := left.(OpNReg); ok {
		return op.OpNReg(left, right, parameters)
	}
	if op, ok := right.(OpNReg); ok {
		return op.OpNReg(left, right, parameters)
	}

	ret, err := regexStage(left, right, parameters)
	if err != nil {
		return nil, err
	}

	return !(ret.(bool)), nil
}

func bitwiseOrStage(left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if op, ok := left.(OpBOr); ok {
		return op.OpBOr(left, right, parameters)
	}
	if op, ok := right.(OpBOr); ok {
		return op.OpBOr(left, right, parameters)
	}
	return float64(int64(left.(float64)) | int64(right.(float64))), nil
}
func bitwiseAndStage(left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if op, ok := left.(OpBAnd); ok {
		return op.OpBAnd(left, right, parameters)
	}
	if op, ok := right.(OpBAnd); ok {
		return op.OpBAnd(left, right, parameters)
	}
	return float64(int64(left.(float64)) & int64(right.(float64))), nil
}
func bitwiseXORStage(left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if op, ok := left.(OpBXor); ok {
		return op.OpBXor(left, right, parameters)
	}
	if op, ok := right.(OpBXor); ok {
		return op.OpBXor(left, right, parameters)
	}
	return float64(int64(left.(float64)) ^ int64(right.(float64))), nil
}
func leftShiftStage(left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if op, ok := left.(OpLShft); ok {
		return op.OpLShft(left, right, parameters)
	}
	if op, ok := right.(OpLShft); ok {
		return op.OpLShft(left, right, parameters)
	}
	return float64(uint64(left.(float64)) << uint64(right.(float64))), nil
}
func rightShiftStage(left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if op, ok := left.(OpRShft); ok {
		return op.OpRShft(left, right, parameters)
	}
	if op, ok := right.(OpRShft); ok {
		return op.OpRShft(left, right, parameters)
	}
	return float64(uint64(left.(float64)) >> uint64(right.(float64))), nil
}

func makeParameterStage(parameterName string) evaluationOperator {

	return func(left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
		value, err := parameters.Get(parameterName)
		if err != nil {
			return nil, err
		}

		return value, nil
	}
}

func makeLiteralStage(literal interface{}) evaluationOperator {
	return func(left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
		return literal, nil
	}
}

func makeFunctionStage(function ExpressionFunction) evaluationOperator {

	return func(left interface{}, right interface{}, parameters Parameters) (interface{}, error) {

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

	return func(left interface{}, right interface{}, parameters Parameters) (ret interface{}, err error) {

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

func separatorStage(left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if op, ok := left.(OpSep); ok {
		return op.OpSep(left, right, parameters)
	}
	if op, ok := right.(OpSep); ok {
		return op.OpSep(left, right, parameters)
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

func inStage(left interface{}, right interface{}, parameters Parameters) (interface{}, error) {
	if op, ok := left.(OpIn); ok {
		return op.OpIn(left, right, parameters)
	}
	if op, ok := right.(OpIn); ok {
		return op.OpIn(left, right, parameters)
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
	// Again we make the assumption here that add has all of them
	if _, ok := left.(OpAdd); ok {
		return true
	}
	if isFloat64(left) && isFloat64(right) {
		return true
	}
	if !isString(left) && !isString(right) {
		return false
	}
	return true
}

func overrideTypeCheck[T interface{}](left interface{}, right interface{}, others typeChecks) bool {
	// Either both are overriden or our right type is a basic type we can handle
	if _, ok := left.(T); ok {
		if _, ok := right.(T); ok || others.right == nil || others.right(right) {
			return true
		}
	}
	if _, ok := right.(T); ok {
		if others.left != nil {
			return others.left(left)
		}
		return true
	}
	if others.combined == nil {
		return others.left(left) && others.right(right)
	} else {
		return others.combined(left, right)
	}
}

func regTypeCheck[T interface{}](left interface{}, right interface{}) bool {
	return overrideTypeCheck[T](left, right, typeChecks{
		left:  isString,
		right: isRegexOrString,
	})
}

func boolTypeCheck[T interface{}](left interface{}, right interface{}) bool {
	return overrideTypeCheck[T](left, right, typeChecks{
		left:  isBool,
		right: isBool,
	})
}

func inTypeCheck[T interface{}](left interface{}, right interface{}) bool {
	return overrideTypeCheck[T](left, right, typeChecks{
		right: isArray,
	})
}

func numericTypeCheck[T interface{}](left interface{}, right interface{}) bool {
	return overrideTypeCheck[T](left, right, typeChecks{
		left:  isFloat64,
		right: isFloat64,
	})
}

func singleTypeCheck[T interface{}, F func(interface{}) bool](val interface{}, f F) bool {
	if _, ok := val.(T); ok {
		return true
	}
	return f(val)
}

/*
Comparison can either be between numbers, or lexicographic between two strings,
but never between the two.
*/
func comparatorTypeCheck[T interface{}](left interface{}, right interface{}) bool {

	// We make the assumption that if you have a Lt you have all of them
	if _, ok := left.(OpLt); ok {
		return true
	}
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
