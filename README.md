# A write-up and transformer for Zelix KlassMaster™ control flow obfuscation

## Introduction
This was done purely just for fun and without any bad intentions!
Zelix KlassMaster™ is one of, if not, the best java bytecode obfuscator out there, but everything has flaws. One of them is their flow obfuscation.
I will be showing you how I managed to deobfuscate a lot of Zelix Klassmasters flow (not all).

## Analysis
Let's start off with the original code. We will be obfuscating a java snake game jar file for this. We are using ZKM 21 (the flow hasn't changed much, if any, since ages anyways, so pretty much ZKM 25 counts as well.)

So, we have the original code of a program seen below.
<img width="888" height="292" alt="image" src="https://github.com/user-attachments/assets/e10e861b-4d8d-479b-a627-41e6ecddf4ec" />
As seen in this image, this code is very readable. But that is about to change. We will be obfuscating the content of this method using Zelix KlassMaster™.

Obfuscated code:
<img width="928" height="898" alt="image" src="https://github.com/user-attachments/assets/c4232d57-2261-4331-9d18-fa59a1eab13b" />
<img width="1146" height="880" alt="image" src="https://github.com/user-attachments/assets/1942a256-bf33-48b0-a57a-5866839ab155" />

Yeah, looks like it's not even the same code. Let's find out how Zelix KlassMaster™ achieves this. For that, we have to take a look at the code in a lower level - java bytecode.
Snippet:
<img width="373" height="205" alt="image" src="https://github.com/user-attachments/assets/7ba86103-8472-4aba-99a4-7d88af70ab71" />

In this code snippet, we can see a few interesting thing.
We have the very normal instructions:

```
iconst_0
anewarray java/lang/Object
invokevirtual o.E ([Ljava/lang/Object;)I
```

These three instructions create an object array of size 0 (as result to Zelix KlassMasters parameter obfuscation). These 3 are pretty normal for now, but what comes after that is a bit strange.
In the original code, the original instructions were:
```
invokevirtual Tuple.getX ()I
if_icmpne E
```
This code snippet checks another integer that's on the stack with `Tuple.getX()`. Then, if they're not equal to each other, `if_icmpne` jumps to the `label E` in the code.
The transformed code shows very different results. We know that `o.E` is `Tuple.getX()`. Now, lets look at the code after the method invocation in the obfuscated snippet. Specifically:
```
iload i8
lload j2
lconst_0
lcmp
iflt M
ifne L
iload i8
ifne D
if_icmpne F
```

### Pattern 1

This is odd. This wasn't here originally. Let's analyze this, starting off with the simplest one:
```
lload j2
lconst_0
lcmp
iflt M
```

After reading the Zelix KlassMaster documentation, I realized what this was. This special pattern uses a long from their `Method Parameter Changes + Long Encryption + Parameter Obfuscation` transformer combination.
The pattern takes `j2`, a `long` and compares it to `0L`.
The `lcmp` instruction is what compares the two `long` values with each other and then pushes an integer onto the stack like so:
```
0, if both values are equal.
-1, if first value is smaller than the other.
1, if first value is larger than the other.
```

After this, `iflt` checks if the result is less than 0. If so, it jumps to the `label M`.
This pattern itself never jumps. I have removed this pattern from about 5 programs that use Zelix KlassMasters flow obfuscation with no consequences whatsoever. So we can just do simple pattern searches for this pattern and remove it.

### Pattern 2

Next, after we remove that, we still have work to do.
<img width="398" height="106" alt="image" src="https://github.com/user-attachments/assets/7be5ebc1-3758-4128-9b33-ce64ad772e02" />

Yeah, looks very normal, but it's not. Me personally, I have never seen a java compiler produce jumps right before some other jump instruction. 
Since we know this isn't normal, we will remove it. But theres a few steps left, specifically, replaced `goto` statements. For this, we will have to keep in mind the previous fake jumps used variable `i8` to fake a jump.

We now have these important pieces of information:
- `i8` is a fake variable used completely for control flow obfuscation purposes only.
- `ifne` is the condition that never jumps.

Theses two are very needed for the next step. We now search for jumps like
```
iload i8
ifne/eq LBL
```
We then replace every jump with var `i8` and an `ifeq` instruction. This will always pass. We insert a `goto` instruction to the `ifeq`'s label and remove the old jumps.
We are now left with an *almost* clean method. Therefore...

### Pattern 3
This pattern is *very* similar to the previous pattern. Just this time, the pattern is:
```
aload someVar
ifnonnull/ifnull LBL
```

We do exactly the same process above for this pattern and we should have come to a completely clean method. This sometimes won't work on smaller methods that have barely any control flow. Some of these patterns can only be removed after removing their
exception obfuscation, so it's smart to remove those beforehand.

## Transformer
To automate this entire process, I wrote a simple transformer for [narumii's deobfuscator base](https://github.com/narumii/Deobfuscator).

```java
package uwu.narumi.deobfuscator.core.other.impl.zkm;

import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;
import uwu.narumi.deobfuscator.api.asm.ClassWrapper;
import uwu.narumi.deobfuscator.api.asm.MethodContext;
import uwu.narumi.deobfuscator.api.asm.matcher.group.SequenceMatch;
import uwu.narumi.deobfuscator.api.asm.matcher.impl.JumpMatch;
import uwu.narumi.deobfuscator.api.asm.matcher.impl.OpcodeMatch;
import uwu.narumi.deobfuscator.api.asm.matcher.impl.VarLoadMatch;
import uwu.narumi.deobfuscator.api.transformer.Transformer;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * @author lvstrng
 */
public class ZelixFlowTransformer extends Transformer {
    // ?
    // > iload // REMOVE
    // > if(?) // REMOVE
    // if(?)
    private static final SequenceMatch INT_COMPARE = SequenceMatch.of(
            OpcodeMatch.of(e -> e.insn().getOpcode() == ILOAD).capture("local"),
            JumpMatch.of(e -> {
                var insn = e.insn();
                if(insn.getOpcode() != IFEQ && insn.getOpcode() != IFNE)
                    return false;

                // stack size still not empty after consuming, doesn't happen in a normal program
                return e.frame().getStackSize() - 1 != 0;
            }).capture("jump")
    );

    // ?
    // > aload              // REMOVE
    // > ifnull/ifnonnull   // REMOVE
    // if(?)
    private static final SequenceMatch OBJ_COMPARE = SequenceMatch.of(
            OpcodeMatch.of(e -> e.insn().getOpcode() == ALOAD).capture("local"),
            JumpMatch.of(e -> {
                var insn = e.insn();
                if(insn.getOpcode() != IFNULL && insn.getOpcode() != IFNONNULL)
                    return false;

                //stack size still not empty after consuming, doesn't happen in a normal program
                return e.frame().getStackSize() - 1 != 0;
            }).capture("jump")
    );

    // This pattern uses the Long var from the MPC changes. Let's be real, this jump never passes.
    private static final SequenceMatch LONG_COMPARE = SequenceMatch.of(
            VarLoadMatch.of(e -> e.insn().getOpcode() == LLOAD).capture("param"),
            OpcodeMatch.of(LCONST_0),
            OpcodeMatch.of(LCMP),
            JumpMatch.of(e -> {
                var op = e.insn().getOpcode();
                return op == IFLT || op == IFLE || op == IFGE || op == IFGT;
            })
    );

    @Override
    protected void transform() throws Exception {
        scopedClasses().parallelStream().forEach(classWrapper -> {
            classWrapper.methods().parallelStream().forEach(methodNode -> {
                try {
                    //clean up long jumps first
                    removeLongCompares(classWrapper, methodNode);
                    //clean ints after
                    removeIntCompares(classWrapper, methodNode);
                    //clean longs again
                    removeLongCompares(classWrapper, methodNode);
                    //clean null-check jumps
                    removeObjCompares(classWrapper, methodNode);
                    //remove last longs
                    removeLongCompares(classWrapper, methodNode);
                } catch (Exception ignored) {}
            });
        });
    }

    private void removeLongCompares(ClassWrapper classWrapper, MethodNode method) {
        LONG_COMPARE.findAllMatches(MethodContext.of(classWrapper, method)).forEach(e -> {
            markChange();
            e.removeAll();
        });
    }

    private void removeObjCompares(ClassWrapper classWrapper, MethodNode methodNode) {
        var neverPassOp = new AtomicInteger(-69);
        var varIdx =      new AtomicInteger(-1);

        var methodContext = MethodContext.of(classWrapper, methodNode);
        OBJ_COMPARE.findAllMatches(methodContext).forEach(match -> {
            if(neverPassOp.get() == -69) {
                neverPassOp.set(match.captures().get("jump").insn().getOpcode());
            }

            if(varIdx.get() == -1) {
                varIdx.set(((VarInsnNode) match.captures().get("local").insn()).var);
            }

            match.removeAll();
            markChange();
        });

        if(neverPassOp.get() == -1 || varIdx.get() == -1)
            return;

        methodContext = MethodContext.of(classWrapper, methodNode);
        objGoto(varIdx.get()).findAllMatches(methodContext).forEach(match -> {
            var jumpCtx = match.captures().get("jump");
            var jump = jumpCtx.insn().asJump();
            var local = match.captures().get("var").insn();

            if(jump.getOpcode() != neverPassOp.get()) {
                methodNode.instructions.insertBefore(local, new JumpInsnNode(GOTO, jump.label));
            }

            markChange();
            match.removeAll();
        });
    }

    private void removeIntCompares(ClassWrapper classWrapper, MethodNode methodNode) {
        var neverPassOp =   new AtomicInteger(-69);
        var varIdx =        new AtomicInteger(-1);

        //remove all single-int fake jumps
        var methodContext = MethodContext.of(classWrapper, methodNode);
        INT_COMPARE.findAllMatches(methodContext).forEach(match -> {
            if(neverPassOp.get() == -69) {
                neverPassOp.set(match.captures().get("jump").insn().getOpcode());
            }

            if(varIdx.get() == -1) {
                varIdx.set(((VarInsnNode) match.captures().get("local").insn()).var);
            }

            match.removeAll();
            markChange();
        });

        //continue if couldn't define local or variable index
        if(varIdx.get() == -1 || neverPassOp.get() == -69)
            return;

        //recompute method context, scan for replaced gotos/other jumps using single-int pattern
        methodContext = MethodContext.of(classWrapper, methodNode);
        intGoto(varIdx.get()).findAllMatches(methodContext).forEach(match -> {
            var jumpCtx = match.captures().get("jump");
            var jump = jumpCtx.insn().asJump();
            var local = match.captures().get("var").insn();

            if(jump.getOpcode() != neverPassOp.get()) {
                methodNode.instructions.insertBefore(local, new JumpInsnNode(GOTO, jump.label));
            }

            markChange();
            match.removeAll();
        });
    }

    private static SequenceMatch objGoto(int varIdx) {
        return SequenceMatch.of(
                OpcodeMatch.of(e -> {
                    if(!(e.insn() instanceof VarInsnNode v))
                        return false;

                    return v.var == varIdx;
                }).capture("var"),
                JumpMatch.of(e -> e.insn().getOpcode() == IFNULL || e.insn().getOpcode() == IFNONNULL).capture("jump")
        );
    }

    //  goto LBL ->
    //
    //  iload x
    //  ifeq/ne OTHER
    //  iload x
    //  ifne/eq LBL
    // OTHER:
    private static SequenceMatch intGoto(int varIdx) {
        return SequenceMatch.of(
                OpcodeMatch.of(e -> {
                    if(!(e.insn() instanceof VarInsnNode v))
                        return false;

                    return v.var == varIdx;
                }).capture("var"),
                JumpMatch.of(e -> e.insn().getOpcode() == IFEQ || e.insn().getOpcode() == IFNE).capture("jump")
        );
    }
}
```

## The end
After all the transformations, this is the cleaned up method we're left with. Very much like the original:
<img width="1151" height="460" alt="image" src="https://github.com/user-attachments/assets/b4c9790d-444e-4acf-90b8-287518749e10" />

I have also somewhat recreated this flow obfuscation technique on my other project [aidsfuscator](https://github.com/LvStrnggg/aidsfuscator/blob/main/src/main/java/dev/lvstrng/aids/transform/impl/flow/LightFlowTransformer.java).

Thanks for your attention, have fun.
