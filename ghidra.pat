diff --git a/Ghidra/Features/Decompiler/src/decompile/cpp/architecture.cc b/Ghidra/Features/Decompiler/src/decompile/cpp/architecture.cc
index 494d160d..97384ddd 100644
--- a/Ghidra/Features/Decompiler/src/decompile/cpp/architecture.cc
+++ b/Ghidra/Features/Decompiler/src/decompile/cpp/architecture.cc
@@ -639,6 +639,12 @@ void Architecture::restoreFromSpec(DocumentStorage &store)
   parseProcessorConfig(store);
   newtrans->setDefaultFloatFormats(); // If no explicit formats registered, put in defaults
   parseCompilerConfig(store);
+  // Perform plugin actions in phases, incase we later need to alter the sequence.
+  // Currently, we need the processor Language defined and all Language-specific user
+  // pcode ops defined before pm.initRules is called.
+  pm.loadPlugin();
+  pm.initPlugin(this);
+  pm.initRules(this);
   // Action stuff will go here
   buildAction(store);
 }
diff --git a/Ghidra/Features/Decompiler/src/decompile/cpp/architecture.hh b/Ghidra/Features/Decompiler/src/decompile/cpp/architecture.hh
index ebd0e843..b8d50b4e 100644
--- a/Ghidra/Features/Decompiler/src/decompile/cpp/architecture.hh
+++ b/Ghidra/Features/Decompiler/src/decompile/cpp/architecture.hh
@@ -33,6 +33,7 @@
 #include "options.hh"
 #include "transform.hh"
 #include "prefersplit.hh"
+#include "plugin_manager.hh"
 
 namespace ghidra {
 
@@ -209,6 +210,7 @@ public:
   UserOpManage userops;		///< Specifically registered user-defined p-code ops
   vector<PreferSplitRecord> splitrecords; ///< registers that we would prefer to see split for this processor
   vector<LanedRegister> lanerecords;	///< Vector registers that have preferred lane sizes
+  PluginManager pm; ///< Experimental plugin manager
   ActionDatabase allacts;	///< Actions that can be applied in this architecture
   bool loadersymbols_parsed;	///< True if loader symbols have been read
 #ifdef CPUI_STATISTICS
diff --git a/Ghidra/Features/Decompiler/src/decompile/cpp/coreaction.cc b/Ghidra/Features/Decompiler/src/decompile/cpp/coreaction.cc
index 436b8431..4116abe3 100644
--- a/Ghidra/Features/Decompiler/src/decompile/cpp/coreaction.cc
+++ b/Ghidra/Features/Decompiler/src/decompile/cpp/coreaction.cc
@@ -5330,7 +5330,7 @@ void ActionDatabase::buildDefaultGroups(void)
 			    "deadcode", "typerecovery", "stackptrflow",
 			    "blockrecovery", "stackvars", "deadcontrolflow", "switchnorm",
 			    "cleanup", "splitcopy", "splitpointer", "merge", "dynamic", "casts", "analysis",
-			    "fixateglobals", "fixateproto", "constsequence",
+			    "fixateglobals", "fixateproto", "constsequence", "pluginrules",
 			    "segment", "returnsplit", "nodejoin", "doubleload", "doubleprecis",
 			    "unreachable", "subvar", "floatprecision",
 			    "conditionalexe", "" };
@@ -5611,6 +5611,11 @@ void ActionDatabase::universalAction(Architecture *conf)
     actcleanup->addRule( new RuleSplitStore("splitpointer") );
     actcleanup->addRule( new RuleStringCopy("constsequence"));
     actcleanup->addRule( new RuleStringStore("constsequence"));
+    if(conf->pm.loaded) {
+      for (std::vector<Rule*>::iterator it = conf->pm.rules.begin(); it != conf->pm.rules.end(); ++it) {
+        actcleanup->addRule(*it);
+      }
+    }
   }
   act->addAction( actcleanup );
 
diff --git a/Ghidra/Features/Decompiler/src/decompile/cpp/plugin_manager.cc b/Ghidra/Features/Decompiler/src/decompile/cpp/plugin_manager.cc
new file mode 100644
index 00000000..2afffd9f
--- /dev/null
+++ b/Ghidra/Features/Decompiler/src/decompile/cpp/plugin_manager.cc
@@ -0,0 +1,84 @@
+#include <iostream>
+#include "plugin_manager.hh"
+#include "architecture.hh"
+
+namespace ghidra
+{
+extern "C" {
+    typedef int (*plugin_init_func)(const Architecture* arch); ///< A plugin initializer
+    typedef int (*plugin_getrules_func)(std::vector<Rule*>& new_rules); ///< Fetches plugin rules
+}
+
+std::ofstream pluginLog;
+
+int PluginManager::loadPlugin()
+{
+    pluginLog.open("/tmp/decomp.log");
+    loaded = false;
+    const char* plugin_path  = getenv("DECOMP_PLUGIN");
+    if (plugin_path == nullptr) {
+        pluginLog << "Failed to find plugin" << std::endl;
+        return 1;
+    }
+    pluginLog << "Plugin loaded" << std::endl;
+    pluginLog.flush();
+    handle = dlopen(plugin_path, RTLD_NOW);
+    if (handle == NULL)
+    {
+        pluginLog << "Could not open plugin: " << dlerror() << std::endl;
+        return 1;
+    }
+    loaded = true;
+    return 0;
+}
+
+int PluginManager::initPlugin(const Architecture* arch)
+{
+    if (! loaded) {
+        return 1;
+    }
+    // only continue if the current architecture is for RISCV systems
+    string arch_description = arch->getDescription();
+    if ((arch_description.find("RISC-V") == std::string::npos) &&
+        (arch_description.find("ghidra") == std::string::npos)) {
+        pluginLog << "Description " << arch_description << " is not RISC-V" << std::endl;
+        pluginLog.flush();
+        return 0;
+    }
+    //std::cout << "Found a RISCV Architecture description:" << arch_description << std::endl;
+    plugin_init_func f_init = reinterpret_cast<plugin_init_func>(dlsym(handle, "plugin_init"));
+    if (f_init == NULL)
+    {
+        pluginLog << "Could not find plugin_init: " << dlerror() << std::endl;
+        pluginLog.flush();
+        return 1;
+    }
+    int initialization_result = f_init(arch);
+    if (initialization_result != 0)
+    {
+        pluginLog << "Plugin initialization failed with return value: " << initialization_result << std::endl;
+        pluginLog.flush();
+        return 1;
+    }
+    return initialization_result;
+}
+
+int PluginManager::initRules(const Architecture* arch) {
+    if (!loaded) return 0;
+    // TODO: verify that this architecture is compatible with RISCV vector instructions
+    pluginLog << "Adding one or more new plugin rules" << std::endl;
+    plugin_getrules_func f_getrules =  reinterpret_cast<plugin_getrules_func>(dlsym(handle, "plugin_getrules"));
+    f_getrules(rules);
+    pluginLog << "Now have " << rules.size() << " plugin rules ready" <<std::endl;
+    pluginLog.flush();
+    return 0;
+}
+
+void PluginManager::unloadPlugin()
+{
+    if (loaded)
+    //std::cout << "closing the plugin" << std::endl;
+        dlclose(handle);
+    loaded = false;
+}
+}
\ No newline at end of file
diff --git a/Ghidra/Features/Decompiler/src/decompile/cpp/plugin_manager.hh b/Ghidra/Features/Decompiler/src/decompile/cpp/plugin_manager.hh
new file mode 100644
index 00000000..a81ed622
--- /dev/null
+++ b/Ghidra/Features/Decompiler/src/decompile/cpp/plugin_manager.hh
@@ -0,0 +1,89 @@
+/* ###
+ * IP: GHIDRA
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+/// \file plugin_manager.hh
+/// \brief Experimental Plugin Support
+
+#ifndef __PLUGIN_MANAGER_HH__
+#define __PLUGIN_MANAGER_HH__
+
+#include <string>
+#include <vector>
+#include <dlfcn.h>
+#include "ruleaction.hh"
+
+namespace ghidra {
+
+// forward declaration
+class Architecture;
+
+/**
+ * @brief Initialize the plugin once the program Architecture is partially constructed.
+ * @details The Architecture description is checked to see if the plugin is relevant,
+ * then the plugin's plugin_init extern C entry point is called.
+ *
+ * @param arch The current Architecture, sufficiently constructed to have resolved
+ * the getDescription() member function.
+ * @return int 0 on success.
+ */
+class PluginManager {
+public:
+    void* handle;
+    bool loaded;
+    std::vector<Rule*> rules;
+    PluginManager() : handle(nullptr), loaded(false) {};
+    ~PluginManager() {
+        handle = nullptr;
+        loaded = false;
+        };
+
+    /**
+     * @brief Load a plugin defined by the environment variable DECOMP_PLUGIN.
+     * @details The plugin memory space is mapped, but no plugin functions or constructors are
+     * called. This probably includes static object constructors.ActionThe loading function may
+     * fail if the plugin depends on main program symbols not exported as dynamic when the main
+     * program was built.
+     *
+     * @return 0 on success, 1 on failure
+     */
+    int loadPlugin();
+    /**
+     * @brief Initialize the plugin once the program Architecture is partially constructed.
+     * @details The Architecture description is checked to see if the plugin is relevant,
+     * then the plugin's plugin_init extern C entry point is called.
+     *
+     * @param arch The current Architecture, sufficiently constructed to have resolved
+     * the getDescription() member function.
+     * @return int 0 on success.
+     */
+    int initPlugin(const Architecture* arch);
+
+    /**
+     * @brief Make available plugin-specific rules
+     *
+     * @return int zero on success
+     */
+    int initRules(const Architecture* arch);
+
+    /**
+     * @brief unload the current plugin.
+     * @warning This deletes destructor code for any object created
+     * by the program, potentially causing a segfault if such
+     * objects remain active after this call.
+     */
+    void unloadPlugin();
+};
+}
+#endif /* __PLUGIN_MANAGER_HH__ */
