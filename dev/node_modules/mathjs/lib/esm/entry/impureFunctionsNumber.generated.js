import _extends from "@babel/runtime/helpers/extends";
/**
 * THIS FILE IS AUTO-GENERATED
 * DON'T MAKE CHANGES HERE
 */
import { config } from './configReadonly.js';
import { createChainClass, createNode, createObjectNode, createRangeNode, createRelationalNode, createReviver, createSymbolNode, createAccessorNode, createAssignmentNode, createBlockNode, createChain, createConditionalNode, createFunctionNode, createIndexNode, createOperatorNode, createArrayNode, createConstantNode, createFunctionAssignmentNode, createParenthesisNode, createSimplifyConstant, createParse, createResolve, createSimplifyCore, createCompile, createEvaluate, createHelpClass, createParserClass, createSimplify, createDerivative, createRationalize, createHelp, createParser, createCumSumTransform, createMapSlicesTransform, createFilterTransform, createForEachTransform, createMeanTransform, createSubsetTransform, createMapTransform, createRangeTransform, createStdTransform, createSumTransform, createMaxTransform, createMinTransform, createVarianceTransform } from '../factoriesNumber.js';
import { e, _false, index, _Infinity, LN10, LOG10E, matrix, _NaN, _null, phi, Range, replacer, ResultSet, SQRT1_2,
// eslint-disable-line camelcase
subset, tau, typed, unaryPlus, version, xor, abs, acos, acot, acsc, add, and, asec, asin, atan, atanh, bigint, bitNot, bitXor, boolean, cbrt, combinations, compare, compareText, cos, cot, csc, cube, divide, equalScalar, erf, exp, filter, forEach, format, gamma, isInteger, isNegative, isPositive, isZero, LOG2E, largerEq, leftShift, log, log1p, map, mean, mod, multiply, not, number, or, pi, pow, random, rightLogShift, SQRT2, sech, sin, size, smallerEq, square, string, subtract, tanh, typeOf, unequal, xgcd, acoth, addScalar, asech, bitAnd, combinationsWithRep, cosh, csch, divideScalar, equalText, expm1, isNumeric, LN2, lcm, log10, mapSlices, multiplyScalar, nthRoot, pickRandom, rightArithShift, sec, sinh, sqrt, tan, unaryMinus, acosh, atan2, bitOr, clone, coth, equal, factorial, hasNumericValue, isNaN, larger, log2, mode, norm, partitionSelect, print, randomInt, round, smaller, subtractScalar, _true, variance, zeta, acsch, catalan, compareNatural, composition, cumsum, floor, hypot, lgamma, median, multinomial, permutations, quantileSeq, sign, std, stirlingS2, asinh, ceil, deepEqual, fix, isPrime, numeric, prod, bellNumbers, gcd, mad, range, sum, corr, max, min } from './pureFunctionsNumber.generated.js';
var math = {}; // NOT pure!
var mathWithTransform = {}; // NOT pure!
var classes = {}; // NOT pure!

export var Chain = createChainClass({
  math,
  typed
});
export var Node = createNode({
  mathWithTransform
});
export var ObjectNode = createObjectNode({
  Node
});
export var RangeNode = createRangeNode({
  Node
});
export var RelationalNode = createRelationalNode({
  Node
});
export var reviver = createReviver({
  classes
});
export var SymbolNode = createSymbolNode({
  Node,
  math
});
export var AccessorNode = createAccessorNode({
  Node,
  subset
});
export var AssignmentNode = createAssignmentNode({
  matrix,
  Node,
  subset
});
export var BlockNode = createBlockNode({
  Node,
  ResultSet
});
export var chain = createChain({
  Chain,
  typed
});
export var ConditionalNode = createConditionalNode({
  Node
});
export var FunctionNode = createFunctionNode({
  Node,
  SymbolNode,
  math
});
export var IndexNode = createIndexNode({
  Node,
  size
});
export var OperatorNode = createOperatorNode({
  Node
});
export var ArrayNode = createArrayNode({
  Node
});
export var ConstantNode = createConstantNode({
  Node
});
export var FunctionAssignmentNode = createFunctionAssignmentNode({
  Node,
  typed
});
export var ParenthesisNode = createParenthesisNode({
  Node
});
export var simplifyConstant = createSimplifyConstant({
  AccessorNode,
  ArrayNode,
  ConstantNode,
  FunctionNode,
  IndexNode,
  ObjectNode,
  OperatorNode,
  SymbolNode,
  config,
  mathWithTransform,
  matrix,
  typed
});
export var parse = createParse({
  AccessorNode,
  ArrayNode,
  AssignmentNode,
  BlockNode,
  ConditionalNode,
  ConstantNode,
  FunctionAssignmentNode,
  FunctionNode,
  IndexNode,
  ObjectNode,
  OperatorNode,
  ParenthesisNode,
  RangeNode,
  RelationalNode,
  SymbolNode,
  config,
  numeric,
  typed
});
export var resolve = createResolve({
  ConstantNode,
  FunctionNode,
  OperatorNode,
  ParenthesisNode,
  parse,
  typed
});
export var simplifyCore = createSimplifyCore({
  AccessorNode,
  ArrayNode,
  ConstantNode,
  FunctionNode,
  IndexNode,
  ObjectNode,
  OperatorNode,
  ParenthesisNode,
  SymbolNode,
  add,
  divide,
  equal,
  isZero,
  multiply,
  parse,
  pow,
  subtract,
  typed
});
export var compile = createCompile({
  parse,
  typed
});
export var evaluate = createEvaluate({
  parse,
  typed
});
export var Help = createHelpClass({
  evaluate
});
export var Parser = createParserClass({
  evaluate,
  parse
});
export var simplify = createSimplify({
  AccessorNode,
  ArrayNode,
  ConstantNode,
  FunctionNode,
  IndexNode,
  ObjectNode,
  OperatorNode,
  ParenthesisNode,
  SymbolNode,
  equal,
  parse,
  replacer,
  resolve,
  simplifyConstant,
  simplifyCore,
  typed
});
export var derivative = createDerivative({
  ConstantNode,
  FunctionNode,
  OperatorNode,
  ParenthesisNode,
  SymbolNode,
  config,
  equal,
  isZero,
  numeric,
  parse,
  simplify,
  typed
});
export var rationalize = createRationalize({
  AccessorNode,
  ArrayNode,
  ConstantNode,
  FunctionNode,
  IndexNode,
  ObjectNode,
  OperatorNode,
  ParenthesisNode,
  SymbolNode,
  add,
  config,
  divide,
  equal,
  isZero,
  mathWithTransform,
  matrix,
  multiply,
  parse,
  pow,
  simplify,
  simplifyConstant,
  simplifyCore,
  subtract,
  typed
});
export var help = createHelp({
  Help,
  mathWithTransform,
  typed
});
export var parser = createParser({
  Parser,
  typed
});
_extends(math, {
  e,
  false: _false,
  index,
  Infinity: _Infinity,
  LN10,
  LOG10E,
  matrix,
  NaN: _NaN,
  null: _null,
  phi,
  replacer,
  SQRT1_2,
  subset,
  tau,
  typed,
  unaryPlus,
  'E': e,
  version,
  xor,
  abs,
  acos,
  acot,
  acsc,
  add,
  and,
  asec,
  asin,
  atan,
  atanh,
  bigint,
  bitNot,
  bitXor,
  boolean,
  cbrt,
  combinations,
  compare,
  compareText,
  cos,
  cot,
  csc,
  cube,
  divide,
  equalScalar,
  erf,
  exp,
  filter,
  forEach,
  format,
  gamma,
  isInteger,
  isNegative,
  isPositive,
  isZero,
  LOG2E,
  largerEq,
  leftShift,
  log,
  log1p,
  map,
  mean,
  mod,
  multiply,
  not,
  number,
  or,
  pi,
  pow,
  random,
  reviver,
  rightLogShift,
  SQRT2,
  sech,
  sin,
  size,
  smallerEq,
  square,
  string,
  subtract,
  tanh,
  typeOf,
  unequal,
  xgcd,
  acoth,
  addScalar,
  asech,
  bitAnd,
  chain,
  combinationsWithRep,
  cosh,
  csch,
  divideScalar,
  equalText,
  expm1,
  isNumeric,
  LN2,
  lcm,
  log10,
  mapSlices,
  multiplyScalar,
  nthRoot,
  pickRandom,
  rightArithShift,
  sec,
  sinh,
  sqrt,
  tan,
  unaryMinus,
  acosh,
  atan2,
  bitOr,
  clone,
  coth,
  equal,
  factorial,
  hasNumericValue,
  isNaN,
  larger,
  log2,
  mode,
  norm,
  partitionSelect,
  print,
  randomInt,
  round,
  simplifyConstant,
  smaller,
  subtractScalar,
  true: _true,
  variance,
  zeta,
  acsch,
  catalan,
  compareNatural,
  composition,
  cumsum,
  floor,
  hypot,
  lgamma,
  median,
  multinomial,
  permutations,
  quantileSeq,
  sign,
  std,
  stirlingS2,
  'PI': pi,
  asinh,
  ceil,
  deepEqual,
  fix,
  isPrime,
  numeric,
  prod,
  bellNumbers,
  gcd,
  mad,
  range,
  sum,
  corr,
  max,
  parse,
  resolve,
  simplifyCore,
  compile,
  evaluate,
  simplify,
  derivative,
  min,
  rationalize,
  help,
  parser,
  config
});
_extends(mathWithTransform, math, {
  cumsum: createCumSumTransform({
    add,
    typed,
    unaryPlus
  }),
  mapSlices: createMapSlicesTransform({
    isInteger,
    typed
  }),
  filter: createFilterTransform({
    typed
  }),
  forEach: createForEachTransform({
    typed
  }),
  mean: createMeanTransform({
    add,
    divide,
    typed
  }),
  subset: createSubsetTransform({}),
  map: createMapTransform({
    typed
  }),
  range: createRangeTransform({
    matrix,
    add,
    config,
    isPositive,
    larger,
    largerEq,
    smaller,
    smallerEq,
    typed
  }),
  std: createStdTransform({
    map,
    sqrt,
    typed,
    variance
  }),
  sum: createSumTransform({
    add,
    config,
    numeric,
    typed
  }),
  max: createMaxTransform({
    config,
    isNaN,
    larger,
    numeric,
    typed
  }),
  min: createMinTransform({
    config,
    isNaN,
    numeric,
    smaller,
    typed
  }),
  variance: createVarianceTransform({
    add,
    divide,
    isNaN,
    mapSlices,
    multiply,
    subtract,
    typed
  })
});
_extends(classes, {
  Range,
  ResultSet,
  Chain,
  Node,
  ObjectNode,
  RangeNode,
  RelationalNode,
  SymbolNode,
  AccessorNode,
  AssignmentNode,
  BlockNode,
  ConditionalNode,
  FunctionNode,
  IndexNode,
  OperatorNode,
  ArrayNode,
  ConstantNode,
  FunctionAssignmentNode,
  ParenthesisNode,
  Help,
  Parser
});
Chain.createProxy(math);
export { embeddedDocs as docs } from '../expression/embeddedDocs/embeddedDocs.js';