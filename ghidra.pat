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
index 00000000..59c593fa
--- /dev/null
+++ b/Ghidra/Features/Decompiler/src/decompile/cpp/plugin_manager.cc
@@ -0,0 +1,119 @@
+#include <iostream>
+#include "spdlog/spdlog.h"
+#include "spdlog/sinks/basic_file_sink.h"
+#include "plugin_manager.hh"
+#include "architecture.hh"
+
+namespace ghidra
+{
+extern "C" {
+    typedef int (*plugin_init_func)(Architecture* arch); ///< A plugin initializer
+    typedef int (*plugin_getrules_func)(std::vector<Rule*>& new_rules); ///< Fetches plugin rules
+    typedef DatatypeUserOp* (*plugin_registerBuiltin_func)(Architecture* arch, int4 i); ///<@brief Register a new builtin
+    typedef void (*plugin_cleanup_func)(); ///<@brief release any heap resources
+}
+
+std::shared_ptr<spdlog::logger> logger;
+
+int PluginManager::loadPlugin()
+{
+    logger = spdlog::basic_logger_mt("pluginManager", "/tmp/ghidraPluginManager.log");
+    logger->set_level(spdlog::level::warn);
+    logger->info("Initialized PluginManager");
+
+    loaded = false;
+    const char* plugin_path  = getenv("DECOMP_PLUGIN");
+    if (plugin_path == nullptr) {
+        logger->warn("Failed to find a plugin");
+        return 1;
+    }
+    logger->info("Plugin loaded");
+    handle = dlopen(plugin_path, RTLD_NOW);
+    if (handle == NULL)
+    {
+        logger->error("Could not open plugin: {0}", dlerror());
+        return 1;
+    }
+    loaded = true;
+    return 0;
+}
+
+int PluginManager::initPlugin(Architecture* arch)
+{
+    if (! loaded) {
+        return 1;
+    }
+    architecture = arch;
+    // quit early if we can be sure the current architecture is *not* a RISC-V architecture
+    string arch_description = arch->getDescription();
+    if ((arch_description.find("RISC-V") == std::string::npos) &&
+        (arch_description.find("ghidra") == std::string::npos)) {
+        logger->warn("Description {0} is not RISC-V", arch_description);
+        return 0;
+    }
+    plugin_init_func f_init = reinterpret_cast<plugin_init_func>(dlsym(handle, "plugin_init"));
+    if (f_init == NULL)
+    {
+        logger->warn("Could not find plugin_init: {0}", dlerror());
+        return 1;
+    }
+    int initialization_result = f_init(arch);
+    if (initialization_result != 0)
+    {
+        logger->error("Plugin initialization failed with return value: {0}", initialization_result);
+        return 1;
+    }
+    return initialization_result;
+}
+
+int PluginManager::initRules(const Architecture* arch) {
+    if (!loaded) return 0;
+    // TODO: verify that this architecture is compatible with RISCV vector instructions
+    plugin_getrules_func f_getrules =  reinterpret_cast<plugin_getrules_func>(dlsym(handle, "plugin_getrules"));
+    f_getrules(rules);
+    logger->trace("Now have {0:d} plugin rules ready",rules.size());
+    return 0;
+}
+
+DatatypeUserOp* PluginManager::registerBuiltin(int4 i) {
+    if (!loaded) return nullptr;
+    logger->info("Registering a new typed builtin");
+    plugin_registerBuiltin_func f_register = reinterpret_cast<plugin_registerBuiltin_func>(dlsym(handle, "plugin_registerBuiltin"));
+    if (f_register == nullptr)
+    {
+        logger->error("Plugin registerBuiltin failed to find the implementing plugin function");
+        return nullptr;
+    }
+    return f_register(architecture, i);
+}
+
+void PluginManager::cleanup()
+{
+    logger->trace("Releasing plugin resources");
+    if (!loaded) return;
+    plugin_cleanup_func f_cleanup = reinterpret_cast<plugin_cleanup_func>(dlsym(handle, "plugin_exit"));
+    if (f_cleanup != nullptr)
+    {
+        f_cleanup();
+    }
+    return;
+}
+
+/// @todo This method can't be called until we are sure all destructors have been called for all clones
+void PluginManager::unloadPlugin()
+{
+    if (loaded)
+        loaded = false;
+}
+
+PluginManager::~PluginManager()
+{
+    logger->trace("Plugin destructor called");
+    if (loaded)
+    {
+        cleanup();
+        handle = nullptr;
+        loaded = false;
+    }
+}
+}
\ No newline at end of file
diff --git a/Ghidra/Features/Decompiler/src/decompile/cpp/plugin_manager.hh b/Ghidra/Features/Decompiler/src/decompile/cpp/plugin_manager.hh
new file mode 100644
index 00000000..92bde3eb
--- /dev/null
+++ b/Ghidra/Features/Decompiler/src/decompile/cpp/plugin_manager.hh
@@ -0,0 +1,99 @@
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
+#include "userop.hh"
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
+    Architecture* architecture;
+    PluginManager() : handle(nullptr), loaded(false) {};
+    ~PluginManager();
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
+
+    /**
+     * @brief Initialize the plugin once the program Architecture is partially constructed.
+     * @details The Architecture description is checked to see if the plugin is relevant,
+     * then the plugin's plugin_init extern C entry point is called.
+     *
+     * @param arch The current Architecture, sufficiently constructed to have resolved
+     * the getDescription() member function.
+     * @return int 0 on success.
+     */
+    int initPlugin(Architecture* arch);
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
+
+    /**
+     * @brief Register a new builtin function from the plugin
+     */
+    DatatypeUserOp* registerBuiltin(int4 i);
+
+    /**
+     * @brief Release any resources other than code
+     */
+    void cleanup();
+};
+}
+#endif /* __PLUGIN_MANAGER_HH__ */
diff --git a/Ghidra/Features/Decompiler/src/decompile/cpp/userop.cc b/Ghidra/Features/Decompiler/src/decompile/cpp/userop.cc
index 9fe8b78d..47a1b57f 100644
--- a/Ghidra/Features/Decompiler/src/decompile/cpp/userop.cc
+++ b/Ghidra/Features/Decompiler/src/decompile/cpp/userop.cc
@@ -477,7 +477,11 @@ UserPcodeOp *UserOpManage::registerBuiltin(uint4 i)
       break;
     }
     default:
-      throw LowlevelError("Bad built-in userop id");
+    {
+      res = glb->pm.registerBuiltin(i);
+      if (res == nullptr)
+        throw LowlevelError("Bad built-in userop id");
+    }
   }
   builtinmap[i] = res;
   return res;
diff --git a/MODULE.bazel b/MODULE.bazel
new file mode 100644
index 00000000..00bb1836
--- /dev/null
+++ b/MODULE.bazel
@@ -0,0 +1,6 @@
+###############################################################################
+# Bazel now uses Bzlmod by default to manage external dependencies.
+# Please consider migrating your external dependencies from WORKSPACE to MODULE.bazel.
+#
+# For more details, please check https://github.com/bazelbuild/bazel/issues/18958
+###############################################################################
