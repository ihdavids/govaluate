package govaluate

/*
Represents a function that can be called from within an expression.
This method must return an error if, for any reason, it is unable to produce exactly one unambiguous result.
An error returned will halt execution of the expression.
*/
type ExpressionFunction func(arguments ...interface{}) (interface{}, error)

/*
Represents a function that can be called from within an expression.
This method must return an error if, for any reason, it is unable to produce exactly one unambiguous result.
An error returned will halt execution of the expression.

Parameters are passed through allowing the function access to the expression parameters internally
This allows for arbitrary scope if desired in an expression.
*/
type ContextExpressionFunction func(params map[string]interface{}, arguments ...interface{}) (interface{}, error)
