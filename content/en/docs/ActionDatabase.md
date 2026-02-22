---
title: Ghidra's Actions and Rules
description: Ghidra's decompiler iteratively applies Actions and Rules to generate C-like source
weight: 35
---

## top-down survey

Ghidra's decompiler starts decompiling a function with a call to `IfcDecompile::execute`.
This function then invokes:

```c
res = dcp->conf->allacts.getCurrent()->perform( *dcp->fd );
```

* `dcp` is an `IfaceDecompData` object holding common decompiler command data
* `dcp->conf` is an `Architecture` object for the current program
* `dcp->conf->allacts` is the `ActionDatabase` for this `Architecture`
* `dcp->conf->allacts.getCurrent()` is the root `Action` within the database
* `dcp->conf->allacts.getCurrent()->perform(...)` executes the code within that root `Action`

Code for the `ActionDatabase` is generally found in `action.hh` and `action.cc`.  The root
`Action` in the ActionDatabase is the `universalAction` named "universal", with the
default root action being "decompile":

```c
const char ActionDatabase::universalname[] = "universal";
...
void ActionDatabase::resetDefaults(void)
{
  Action *universalAction = (Action *)0;
  map<string,Action *>::iterator iter;
  iter = actionmap.find(universalname);
  if (iter != actionmap.end())
    universalAction = (*iter).second;
  for(iter = actionmap.begin();iter!=actionmap.end();++iter) {
    Action *curAction = (*iter).second;
    if (curAction != universalAction)
      delete curAction;         // Clear out any old (modified) root actions
  }
  actionmap.clear();
  registerAction(universalname, universalAction);

  buildDefaultGroups();
  setCurrent("decompile");      // The default root action
}
```

This `universalAction` is defined in `coreaction.cc`.

```c
void ActionDatabase::universalAction(Architecture *conf)
```

>Note: This is a good point for the reader to browse through the Doxygen descriptions
>      of Action, ActionGroup, ActionPool, and Rule to get a basic understanding of the
>      hierarchy.

The `ActionDatabase` defines the "decompile" group has having multiple "members", starting
with "base" and including "cleanup" and "constsequence".  The "constsequence" group is
used exclusively by the existing Ghidra code to transform sequences of loads and stores
into builtin memcpy or string copy functions.

The function `ActionDatabase::universalAction` binds two "constsequence" rules to the
default universal action:

```c
/// Construct the \b universal Action that contains all possible components
/// \param conf is the Architecture that will use the Action
void ActionDatabase::universalAction(Architecture *conf)

{
  vector<Rule *>::iterator iter;
  ActionGroup *act;
  ActionGroup *actmainloop;
  ActionGroup *actfullloop;
  ActionPool *actprop,*actprop2;
  ActionPool *actcleanup;
  ActionGroup *actstackstall;
...
  act = new ActionRestartGroup(Action::rule_onceperfunc,"universal",1);
  registerAction(universalname,act);
  act->addAction( new ActionStart("base"));
...
  actstackstall = new ActionGroup(Action::rule_repeatapply,"stackstall");
  actprop = new ActionPool(Action::rule_repeatapply,"oppool1");
  actprop->addRule( new RuleEarlyRemoval("deadcode"));
  for(iter=conf->extra_pool_rules.begin();iter!=conf->extra_pool_rules.end();++iter)
          actprop->addRule( *iter ); // Add CPU specific rules
  conf->extra_pool_rules.clear(); // Rules are now absorbed into universal
  actstackstall->addAction( actprop );
...
  act->addAction( new ActionStartCleanUp("cleanup") );
  actcleanup = new ActionPool(Action::rule_repeatapply,"cleanup");
  ...
  actcleanup->addRule( new RuleStringCopy("constsequence"));
  actcleanup->addRule( new RuleStringStore("constsequence"));
  // code added via patch to load additional plugin rules similar to "constsequence"
  if(conf->pm.loaded) {
    for (std::vector<Rule*>::iterator it = conf->pm.rules.begin(); it != conf->pm.rules.end(); ++it) {
        actcleanup->addRule(*it);
    }
  }
  // end of added plugin code
  act->addAction( actcleanup );
  ...
  // final actions performed
  act->addAction( new ActionNameVars("merge") );
  act->addAction( new ActionSetCasts("casts") );
  act->addAction( new ActionFinalStructure("blockrecovery") );
  act->addAction( new ActionPrototypeWarnings("protorecovery") );
  act->addAction( new ActionStop("base") );
}
```

This shows:

* The existing Ghidra code allows for CPU-specific rules to be added to the "stackstall" ActionGroup.
  No such rules are currently defined, so nothing gets added.
* The existing Ghidra code adds two "constsequence" rules to the "cleanup" `ActionPool`.  One Rule
  generally searches for constant memcpy sequences and the other for constant strcpy sequences.
* The experimental plugin manager can insert its rules to the "cleanup" `ActionPool`, immediately
  after the existing "constsequence" rules.

## Runtime statistics

The decompiler's ActionDatabase collects statistics on the loaded rules and actions.
We can get a snapshot of this on the first insertion of a vector loop transform during `whisper.cpp::main` decompilation.

>Note: The snapshot below is taken during vectorTransform rule processing, so none of the following Rules have been
>      Tested or Applied at that point.

The (abridged) output from `conf->allacts.getCurrent()->printStatistics(...)` is:

```text
universal Tested=1 Applied=0
start Tested=1 Applied=0
constbase Tested=1 Applied=0
defaultparams Tested=1 Applied=0
extrapopsetup Tested=1 Applied=0
prototypetypes Tested=1 Applied=0
funclink Tested=1 Applied=0
fullloop Tested=1 Applied=3
mainloop Tested=4 Applied=10
unreachable Tested=14 Applied=0
varnodeprops Tested=14 Applied=0
heritage Tested=14 Applied=0
...

startcleanup Tested=1 Applied=0
cleanup Tested=1 Applied=0
...
vectorTransforms Tested=2 Applied=0
...
mapglobals Tested=0 Applied=0
dynamicsymbols Tested=0 Applied=0
namevars Tested=0 Applied=0
setcasts Tested=0 Applied=0
finalstructure Tested=0 Applied=0
prototypewarnings Tested=0 Applied=0
stop Tested=0 Applied=0
```

## Action and Rule structure

Actions apply to the entire function, while Rules trigger on specific PcodeOps and make
more local transforms.  The universal action contains all actions and rules applicable
for decompilation, executed in the sequence shown below.  Some of these container actions are *repeating*,
meaning they will continue to trigger until all actions or rules within the container report
no further transforms.

The current plugin manager adds new Rules to the end of [actcleanup](#actcleanup).  Therefore the PCode
and block structure is mostly finished at this point.  Note that Type casting analysis *follows* [actcleanup](#actcleanup), so that new Varnodes are likely inserted into any PcodeOp blocks modified
by the plugins.

### rootaction

> Normal decompilation actions flow from this *non-repeating* restartable action.
> It contains several *repeating* ActionGroups that trigger until no further changes are
> observed.

* ActionStart
* ActionConstbase
* ActionDefaultParams
* ActionExtraPopSetup
* ActionPrototypeTypes
* ActionFuncLink
* [fullloop](#fullloop)
* ActionStartCleanUp
* [actcleanup](#actcleanup)
* ActionPreferComplement
* ActionStructureTransform
* ActionNormalizeBranches
* ActionAssignHigh
* ActionMergeRequired
* ActionMarkExplicit
* ActionMarkImplied
* ActionMergeMultiEntry
* ActionMergeCopy
* ActionDominantCopy
* ActionDynamicSymbols
* ActionMarkIndirectOnly
* ActionMergeAdjacent
* ActionMergeType
* ActionHideShadow
* ActionCopyMarker
* ActionOutputPrototype
* ActionInputPrototype
* ActionMapGlobals
* ActionDynamicSymbols
* ActionNameVars
* ActionSetCasts
* ActionFinalStructure
* ActionPrototypeWarnings
* ActionStop

### fullloop

> This repeatable collection of Actions appears to contain and extend [mainloop](#mainloop)

* [mainloop](#mainloop)
* ActionLikelyTrash
* ActionDirectWrite
* ActionDeadCode
* ActionDoNothing
* ActionSwitchNorm
* ActionReturnSplit
* ActionUnjustifiedParams
* ActionStartTypes
* ActionActiveReturn

### mainloop

> This repeatable collection of Actions should not be confused with its parent [fullloop](#fullloop)

* ActionUnreachable
* ActionVarnodeProps
* ActionHeritage
* ActionParamDouble
* ActionSegmentize
* ActionInternalStorage
* ActionForceGoto
* ActionDirectWrite
* ActionActiveParam
* ActionReturnRecovery
* ActionRestrictLocal
* ActionDeadCode
* ActionDynamicMapping
* ActionRestructureVarnode
* ActionSpacebase
* ActionNonzeroMask
* ActionInferTypes
* [stackstall](#stackstall)
* ActionRedundBranch
* ActionBlockStructure
* ActionConstantPtr
* [oppool2](#oppool2)
* ActionDeterminedBranch
* ActionUnreachable
* ActionNodeJoin
* ActionConditionalExe
* ActionConditionalConst

### stackstall

> A collection of repeating actions inserted into [mainloop](#mainloop)

* [oppool1](#oppool1)
* ActionLaneDivide
* ActionMultiCse
* ActionShadowVar
* ActionDeindirect
* ActionStackPtrFlow

### oppool1

> A collection of repeating operator rules inserted into [stackstall](#stackstall)
* RuleEarlyRemoval
* RuleTermOrder
* RuleSelectCse
* RuleCollectTerms
* RulePullsubMulti
* RulePullsubIndirect
* RulePushMulti
* RuleSborrow
* RuleScarry
* RuleIntLessEqual
* RuleTrivialArith
* RuleTrivialBool
* RuleTrivialShift
* RuleSignShift
* RuleTestSign
* RuleIdentityEl
* RuleOrMask
* RuleAndMask
* RuleOrConsume
* RuleOrCollapse
* RuleAndOrLump
* RuleShiftBitops
* RuleRightShiftAnd
* RuleNotDistribute
* RuleHighOrderAnd
* RuleAndDistribute
* RuleAndCommute
* RuleAndPiece
* RuleAndZext
* RuleAndCompare
* RuleDoubleSub
* RuleDoubleShift
* RuleDoubleArithShift
* RuleConcatShift
* RuleLeftRight
* RuleShiftCompare
* RuleShift2Mult
* RuleShiftPiece
* RuleMultiCollapse
* RuleIndirectCollapse
* Rule2Comp2Mult
* RuleSub2Add
* RuleCarryElim
* RuleBxor2NotEqual
* RuleLess2Zero
* RuleLessEqual2Zero
* RuleSLess2Zero
* RuleEqual2Zero
* RuleEqual2Constant
* RuleThreeWayCompare
* RuleXorCollapse
* RuleAddMultCollapse
* RuleCollapseConstants
* RuleTransformCpool
* RulePropagateCopy
* RuleZextEliminate
* RuleSlessToLess
* RuleZextSless
* RuleBitUndistribute
* RuleBooleanUndistribute
* RuleBooleanDedup
* RuleBoolZext
* RuleBooleanNegate
* RuleLogic2Bool
* RuleSubExtComm
* RuleSubCommute
* RuleConcatCommute
* RuleConcatZext
* RuleZextCommute
* RuleZextShiftZext
* RuleShiftAnd
* RuleConcatZero
* RuleConcatLeftShift
* RuleSubZext
* RuleSubCancel
* RuleShiftSub
* RuleHumptyDumpty
* RuleDumptyHump
* RuleHumptyOr
* RuleNegateIdentity
* RuleSubNormal
* RulePositiveDiv
* RuleDivTermAdd
* RuleDivTermAdd2
* RuleDivOpt
* RuleSignForm
* RuleSignForm2
* RuleSignDiv2
* RuleDivChain
* RuleSignNearMult
* RuleModOpt
* RuleSignMod2nOpt
* RuleSignMod2nOpt2
* RuleSignMod2Opt
* RuleSwitchSingle
* RuleCondNegate
* RuleBoolNegate
* RuleLessEqual
* RuleLessNotEqual
* RuleLessOne
* RuleRangeMeld
* RuleFloatRange
* RulePiece2Zext
* RulePiece2Sext
* RulePopcountBoolXor
* RuleXorSwap
* RuleLzcountShiftBool
* RuleFloatSign
* RuleOrCompare
* RuleSubvarAnd
* RuleSubvarSubpiece
* RuleSplitFlow
* RulePtrFlow
* RuleSubvarCompZero
* RuleSubvarShift
* RuleSubvarZext
* RuleSubvarSext
* RuleNegateNegate
* RuleConditionalMove
* RuleOrPredicate
* RuleFuncPtrEncoding
* RuleSubfloatConvert
* RuleFloatCast
* RuleIgnoreNan
* RuleUnsigned2Float
* RuleInt2FloatCollapse
* RulePtraddUndo
* RulePtrsubUndo
* RuleSegment
* RulePiecePathology
* RuleDoubleLoad
* RuleDoubleStore
* RuleDoubleIn
RuleDoubleOut
* **extra_pool_rules inserted here (not currently used?)**

### oppool2

> A collection of repeating operator rules inserted into [mainloop](#mainloop)

* RulePushPtr
* RuleStructOffset0
* RulePtrArith
* RuleLoadVarnode
* RuleStoreVarnode

### actcleanup

> A collection of repeating operator rules inserted into the [rootaction](#rootaction)

* RuleMultNegOne
* RuleAddUnsigned
* Rule2Comp2Sub
* RuleDumptyHumpLate
* RuleSubRight
* RuleFloatSignCleanup
* RuleExpandLoad
* RulePtrsubCharConstant
* RuleExtensionPush
* RulePieceStructure
* RuleSplitCopy
* RuleSplitLoad
* RuleSplitStore
* RuleStringCopy
* RuleStringStore
* **Plugin Manager loads user rules at this point**
