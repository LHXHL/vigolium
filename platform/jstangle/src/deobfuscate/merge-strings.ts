import * as m from '@codemod/matchers';
import type { Transform, TransformState } from '../ast-utils';
import type { Visitor } from '../ast-utils/babel';

// "a" + "b" -> "ab"
// (a + "b") + "c" -> a + "bc"
//  left ^      ^ right (path)
export default {
  name: 'merge-strings',
  tags: ['safe'],
  minLevel: 'strict',
  visitor(): Visitor<TransformState> {
    const left = m.capture(m.stringLiteral());
    const right = m.capture(m.stringLiteral());

    const matcher = m.binaryExpression(
      '+',
      m.or(left, m.binaryExpression('+', m.anything(), left)),
      right,
    );

    return {
      BinaryExpression: {
        exit(path) {
          if (!matcher.match(path.node)) return;
          left.current!.value += right.current!.value;
          right.current!.value = ''; // Otherwise it concatenates multiple times for some reason
          path.replaceWith(path.node.left);
          path.skip();
          this.changes++;
        },
      },
    };
  },
} satisfies Transform;
