/**
 * @file riscv_doc.hh
 * 
 * @page plugins Ghidra Plugins
 * 
 * @section riscv_vector_transforms RISC-V Vector Transforms
 * 
 * This plugin generates additional rules and transforms intended to translate
 * common vector instruction sequences into recognizable calls to \em builtin_memcpy.
 *
 * @subsection riscv_usage Plugin Usage
 *
 * This plugin is accessed via the \ref PluginManager class and loaded as a sharable object library
 * defined by the <tt>DECOMP_PLUGIN</tt> environment variable.
 * Key features are:
 * - loaded near the end of the \ref ghidra::Architecture constructor, after the processor language is known
 * - initialized during \ref ghidra::Architecture::init, allowing basic survey of the architecture
 * - rules are added to the \ref ghidra::PluginManager.rules vector shortly after initialization and before the \ref ghidra::ActionDatabase
 *   is populated, incorporating any such rules as part of the \c pluginrules ActionGroup
 * - the plugin is unloaded - unmapped - on a call to \ref ghidra::PluginManager.unloadPlugin.  This will erase any object destructors
 *   used by objects created within the plugin, making later destruction segfault.
 * 
 * @subsection initialization_deps Initialization Dependencies
 * Plugin operations are triggered at different points within Architecture object construction and initialization.
 * * the PluginManager is constructed as part of Architecture construction
 * * user pcode ops like 'vsetvli*' are initialized during Architecture.init(), during the restoreFromSpec call
 * * plugin actions are collected via the buildAction method, during the restoreFromSpec call, shortly after the user pcode ops are
 * initialized.
 */