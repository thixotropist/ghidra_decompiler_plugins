---
title: Ghidra's Actions and Rules
weight: 30
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
}
```

This shows:

* The existing Ghidra code allows for CPU-specific rules to be added to the "stackstall" ActionGroup.
  No such rules are currently defined, so nothing gets added.
* The existing Ghidra code adds two "constsequence" rules to the "cleanup" `ActionPool`.  One Rule
  generally searches for constant memcpy sequences and the other for constant strcpy sequences.
* The experimental plugin manager can insert its rules to the "cleanup" `ActionPool`, immediately
  after the existing "constsequence" rules.

>TODO: remove unused "pluginrules" from the members of the "decompile" group.
>TODO: Understand whether the plugin rules should be added to the `ActionDatabase` "stackstall" `ActionGroup` rather than the "cleanup" `ActionPool`.
>TODO: Locate the Actions or Rules establishing block structure and assigning MULTIEQUAL or Phi PcodeOps.

## Default Groups and Actions

* decompile
    * base
    * protorecovery
    * protorecovery_a
    * deindirect
    * localrecovery
    * deadcode
    * typerecovery
    * stackptrflow
    * blockrecovery
    * stackvars
    * deadcontrolflow
    * switchnorm
    * cleanup
    * splitcopy
    * splitpointer
    * merge
    * dynamic
    * casts
    * analysis
    * fixateglobals
    * fixateproto
    * constsequence
    * pluginrules
    * segment
    * returnsplit
    * nodejoin
    * doubleload
    * doubleprecis
    * unreachable
    * subvar
    * floatprecision
    * conditionalexe
