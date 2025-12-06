/**
 * @file riscv_doc.hh
 *
 * @page plugins Ghidra Plugins
 *
 * @section riscv_vector_transforms RISC-V Vector Transforms
 *
 * This plugin generates additional rules and transforms intended to translate
 * common vector instruction sequences into recognizable calls to \em vector_memcpy and \em vector_memset.
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
 * - Additional datatyped builtins may be defined by the plugin and registered for use during Rule execution.
 *   Datatyped builtins are similar to user pcodes, but with type information assigned to the parameters and outputs.
 * - the plugin destructor is called during \ref ghidra::Architecture destruction, allowing the plugin a chance to delete
 *   any heap objects it owns.
 * - the plugin is unloaded - unmapped - on a call to \ref ghidra::PluginManager.unloadPlugin.  This will erase any object destructors
 *   used by objects created within the plugin, making later destruction segfault.  Therefore \ref ghidra::PluginManager.unloadPlugin is
 *   not currently called.
 *
 * @subsection initialization_deps Initialization Dependencies
 * Plugin operations are triggered at different points within Architecture object construction and initialization.
 * * the PluginManager is constructed as part of Architecture construction
 * * user pcode ops like 'vsetvli*' are initialized during Architecture.init(), during the restoreFromSpec call
 * * plugin actions are collected via the buildAction method, during the restoreFromSpec call, shortly after the user pcode ops are
 *   initialized.
 */