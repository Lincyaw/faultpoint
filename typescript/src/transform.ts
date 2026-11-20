import { createHash } from "node:crypto";

import ts from "typescript";

import { POINTS_SYMBOL, type Placement } from "./config.js";
import { pointId } from "./rules.js";

const CODE_WIDTH = 120;
const COMPARISONS: ReadonlySet<ts.SyntaxKind> = new Set([
  ts.SyntaxKind.EqualsEqualsToken, ts.SyntaxKind.EqualsEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsToken,
  ts.SyntaxKind.ExclamationEqualsEqualsToken, ts.SyntaxKind.LessThanToken, ts.SyntaxKind.GreaterThanToken,
  ts.SyntaxKind.LessThanEqualsToken, ts.SyntaxKind.GreaterThanEqualsToken, ts.SyntaxKind.InstanceOfKeyword,
  ts.SyntaxKind.InKeyword,
]);

/** One point of the manifest, as spec/manifest.schema.json defines. */
export interface PointEntry {
  id: string;
  kind: string;
  file: string;
  line: number;
  function: string;
  code: string;
}

interface Scope {
  name: string;
  check: string | null;
  literals: number;
}

type FunctionLike = ts.FunctionDeclaration | ts.MethodDeclaration | ts.FunctionExpression | ts.ArrowFunction
  | ts.GetAccessorDeclaration;

function functionLike(node: ts.Node): node is FunctionLike {
  return ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node) || ts.isFunctionExpression(node)
    || ts.isArrowFunction(node) || ts.isGetAccessorDeclaration(node);
}

/** The values a function returns itself, not those of the functions it holds. */
function ownReturnValues(declaration: FunctionLike): ts.Expression[] {
  const body = declaration.body;
  if (body === undefined) {
    return [];
  }
  if (!ts.isBlock(body)) {
    return [body];
  }
  const values: ts.Expression[] = [];
  const collect = (node: ts.Node): void => {
    if (ts.isReturnStatement(node) && node.expression !== undefined) {
      values.push(node.expression);
    }
    if (!functionLike(node) && !ts.isClassLike(node)) {
      ts.forEachChild(node, collect);
    }
  };
  ts.forEachChild(body, collect);
  return values;
}

/** Whether an expression is a boolean by its syntax, since the transform runs without types. */
function booleanShaped(expression: ts.Expression): boolean {
  if (ts.isParenthesizedExpression(expression)) {
    return booleanShaped(expression.expression);
  }
  if (expression.kind === ts.SyntaxKind.TrueKeyword || expression.kind === ts.SyntaxKind.FalseKeyword) {
    return true;
  }
  if (ts.isPrefixUnaryExpression(expression)) {
    return expression.operator === ts.SyntaxKind.ExclamationToken;
  }
  if (ts.isBinaryExpression(expression)) {
    const operator = expression.operatorToken.kind;
    if (operator === ts.SyntaxKind.AmpersandAmpersandToken || operator === ts.SyntaxKind.BarBarToken) {
      return booleanShaped(expression.left) && booleanShaped(expression.right);
    }
    return COMPARISONS.has(operator);
  }
  return false;
}

function constantLoop(loop: ts.IterationStatement): boolean {
  return ts.isForStatement(loop) && loop.condition !== undefined && ts.isBinaryExpression(loop.condition)
    && ts.isNumericLiteral(loop.condition.right);
}

/** Places branch, check, loop and clock points in one module. */
class Placer {
  readonly scopes: Scope[] = [];
  readonly ordinals = new Map<string, number>();
  readonly points: PointEntry[] = [];
  readonly printer = ts.createPrinter();

  constructor(readonly service: string, readonly path: string, readonly source: ts.SourceFile,
    readonly factory: ts.NodeFactory, readonly placement: Placement) {}

  place(kind: string, node: ts.Node, anchor: ts.Node | null): string {
    const name = this.scopes.at(-1)?.name ?? "<module>";
    let locator = `${this.path}:${name}`;
    if (anchor !== null) {
      const text = this.printer.printNode(ts.EmitHint.Unspecified, anchor, this.source);
      const base = `${locator}#${createHash("sha256").update(text).digest("hex").slice(0, 8)}`;
      const ordinal = this.ordinals.get(base) ?? 0;
      this.ordinals.set(base, ordinal + 1);
      locator = ordinal === 0 ? base : `${base}.${ordinal}`;
    }
    const id = pointId(this.service, kind, locator);
    const line = this.source.getLineAndCharacterOfPosition(node.getStart(this.source)).line + 1;
    const code = node.getText(this.source).split("\n")[0].slice(0, CODE_WIDTH);
    this.points.push({ id, kind, file: this.path, line, function: name, code });
    return id;
  }

  call(name: string, point: string, ...arguments_: ts.Expression[]): ts.CallExpression {
    const factory = this.factory;
    const points = factory.createElementAccessExpression(factory.createIdentifier("globalThis"),
      factory.createCallExpression(factory.createPropertyAccessExpression(factory.createIdentifier("Symbol"), "for"),
        undefined, [factory.createStringLiteral(POINTS_SYMBOL)]));
    return factory.createCallExpression(factory.createPropertyAccessExpression(points, name), undefined,
      [factory.createStringLiteral(point), ...arguments_]);
  }

  functionName(declaration: FunctionLike): string {
    const outer = this.scopes.at(-1);
    if ((ts.isFunctionDeclaration(declaration) || ts.isMethodDeclaration(declaration)
      || ts.isGetAccessorDeclaration(declaration)) && declaration.name !== undefined) {
      const owner = ts.isClassLike(declaration.parent) && declaration.parent.name !== undefined
        ? `${declaration.parent.name.text}.` : "";
      return `${owner}${declaration.name.getText(this.source)}`;
    }
    if (ts.isVariableDeclaration(declaration.parent) && ts.isIdentifier(declaration.parent.name)) {
      return declaration.parent.name.text;
    }
    if (outer === undefined) {
      return "<module>.fn";
    }
    outer.literals += 1;
    return `${outer.name}.fn${outer.literals}`;
  }

  checkable(declaration: FunctionLike): boolean {
    const asynchronous = (ts.getCombinedModifierFlags(declaration) & ts.ModifierFlags.Async) !== 0;
    const values = ownReturnValues(declaration);
    return !asynchronous && declaration.asteriskToken === undefined && values.length > 0
      && values.every(booleanShaped) && values.some(
        (value) => value.kind !== ts.SyntaxKind.TrueKeyword && value.kind !== ts.SyntaxKind.FalseKeyword);
  }

  /** Whether a node reads the clock by the configured names: `A.b` and `f` name calls, `new C` an
   * argument-free construction. */
  clockRead(node: ts.Node): boolean {
    if (ts.isCallExpression(node)) {
      return this.placement.clock.includes(node.expression.getText(this.source));
    }
    return ts.isNewExpression(node) && (node.arguments?.length ?? 0) === 0
      && this.placement.clock.includes(`new ${node.expression.getText(this.source)}`);
  }

  loopBody(statement: ts.Statement, point: string): ts.Block {
    const marker = this.factory.createExpressionStatement(this.call("loop", point));
    return ts.isBlock(statement)
      ? this.factory.updateBlock(statement, [marker, ...statement.statements])
      : this.factory.createBlock([marker, statement], true);
  }

  placeLoop(loop: ts.IterationStatement, point: string): ts.Statement {
    const factory = this.factory;
    const body = this.loopBody(loop.statement, point);
    if (ts.isForStatement(loop)) {
      return factory.updateForStatement(loop, loop.initializer, loop.condition, loop.incrementor, body);
    }
    if (ts.isForOfStatement(loop)) {
      return factory.updateForOfStatement(loop, loop.awaitModifier, loop.initializer, loop.expression, body);
    }
    if (ts.isForInStatement(loop)) {
      return factory.updateForInStatement(loop, loop.initializer, loop.expression, body);
    }
    if (ts.isWhileStatement(loop)) {
      return factory.updateWhileStatement(loop, loop.expression, body);
    }
    if (ts.isDoStatement(loop)) {
      return factory.updateDoStatement(loop, body, loop.expression);
    }
    throw new Error(`unknown loop kind ${ts.SyntaxKind[loop.kind]}`);
  }

  visit(node: ts.Node, context: ts.TransformationContext): ts.Node {
    const recurse = (child: ts.Node): ts.Node => this.visit(child, context);
    const factory = this.factory;
    if (functionLike(node)) {
      const scope: Scope = { name: this.functionName(node), check: null, literals: 0 };
      this.scopes.push(scope);
      scope.check = this.placement.check && this.checkable(node) ? this.place("check", node, null) : null;
      let updated = ts.visitEachChild(node, recurse, context);
      if (scope.check !== null && ts.isArrowFunction(updated) && !ts.isBlock(updated.body)) {
        updated = factory.updateArrowFunction(updated, updated.modifiers, updated.typeParameters,
          updated.parameters, updated.type, updated.equalsGreaterThanToken, this.call("check", scope.check, updated.body));
      }
      this.scopes.pop();
      return updated;
    }
    if (ts.isReturnStatement(node)) {
      const updated = ts.visitEachChild(node, recurse, context);
      const check = this.scopes.at(-1)?.check ?? null;
      return check !== null && updated.expression !== undefined
        ? factory.updateReturnStatement(updated, this.call("check", check, updated.expression))
        : updated;
    }
    if (ts.isIfStatement(node) && this.scopes.length > 0 && this.placement.branch) {
      const then = node.thenStatement;
      const guards = ts.isThrowStatement(then) || (ts.isBlock(then) && then.statements.some(ts.isThrowStatement));
      const point = guards ? this.place("branch", node, node.expression) : null;
      const updated = ts.visitEachChild(node, recurse, context);
      return point === null ? updated : factory.updateIfStatement(updated,
        this.call("branch", point, updated.expression), updated.thenStatement, updated.elseStatement);
    }
    if (ts.isIterationStatement(node, false) && this.scopes.length > 0 && this.placement.loop && !constantLoop(node)) {
      const point = this.place("loop", node, node);
      return this.placeLoop(ts.visitEachChild(node, recurse, context), point);
    }
    if (this.scopes.length > 0 && this.clockRead(node)) {
      const point = this.place("clock", node, node);
      return this.call("clock", point, ts.visitEachChild(node, recurse, context) as ts.Expression);
    }
    return ts.visitEachChild(node, recurse, context);
  }
}

/** A module's instrumented code and its points; no code when it holds no point. `path` is the
 * module's path relative to the source root, which point ids are built from. */
export function instrumentModule(code: string, path: string, service: string,
  placement: Placement): { code: string | null; points: PointEntry[] } {
  const source = ts.createSourceFile(path, code, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  let placer: Placer | undefined;
  const result = ts.transform(source, [(context) => (root) => {
    placer = new Placer(service, path, source, context.factory, placement);
    return placer.visit(root, context) as ts.SourceFile;
  }]);
  if (placer === undefined || placer.points.length === 0) {
    return { code: null, points: [] };
  }
  return { code: ts.createPrinter().printFile(result.transformed[0]), points: placer.points };
}
