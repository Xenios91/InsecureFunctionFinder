
//@keybinding
//@menupath
//@toolbar

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.bookmark.BookmarkDeleteCmd;
import ghidra.app.plugin.core.bookmark.BookmarkEditCmd;
import ghidra.app.script.GhidraScript;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SymbolIterator;

/**
 * The Class ClangTokenGenerator.
 */
public class VulnFunctionFinder extends GhidraScript {

	private DecompInterface decomplib;
	private final List<String> functionsOfInterest = Arrays.asList("printf", "atoi", "atol", "atoll", "gets", "strcat",
			"memcpy", "strcpy", "sprintf", "system", "exec", "strncpy", "vsprintf", "strlen");

	/**
	 * Decompile function.
	 *
	 * @param f the function to decompile.
	 * @return the high function of the decompiled function.
	 */
	public HighFunction decompileFunction(final Function f) {
		HighFunction hfunction = null;

		try {
			final DecompileResults dRes = this.decomplib.decompileFunction(f,
					this.decomplib.getOptions().getDefaultTimeout(), getMonitor());
			hfunction = dRes.getHighFunction();
		} catch (final Exception exc) {
			printf("EXCEPTION IN DECOMPILATION!\n");
			exc.printStackTrace();
		}

		return hfunction;
	}

	/**
	 * Sets the up decompiler.
	 *
	 * @param program the program to decompile.
	 * @return the decomp interface
	 */
	private DecompInterface setUpDecompiler(final Program program) {
		final DecompInterface decompInterface = new DecompInterface();

		DecompileOptions options;
		options = new DecompileOptions();
		final PluginTool tool = this.state.getTool();
		if (tool != null) {
			final OptionsService service = tool.getService(OptionsService.class);
			if (service != null) {
				final ToolOptions opt = service.getOptions("Decompiler");
				options.grabFromToolAndProgram(null, opt, program);
			}
		}
		decompInterface.setOptions(options);

		decompInterface.toggleCCode(true);
		decompInterface.toggleSyntaxTree(true);
		decompInterface.setSimplificationStyle("decompile");

		return decompInterface;
	}

	public Map<AddressSetView, String> getFunctions() {
		final SymbolIterator symbolIter = this.currentProgram.getSymbolTable().getAllSymbols(false);
		final FunctionManager functionManager = this.getCurrentProgram().getFunctionManager();
		final Map<AddressSetView, String> results = new HashMap<>();

		symbolIter.forEachRemaining(symbol -> {

			final Function function = functionManager.getFunctionAt(symbol.getAddress());

			// if function is null or it is an external function we skip it.
			if (function == null || function.toString().contains("EXTERNAL")) {
				return;
			}

			// get all called functions.
			final Set<Function> calledFunctions = function.getCalledFunctions(null);

			// iterate looking for functions of interest being called.
			for (final String functionOfInterestName : this.functionsOfInterest) {
				for (final Function calledFunction : calledFunctions) {

					String calledFunctionName = calledFunction.toString();

					if (calledFunctionName.contains("EXTERNAL")) {
						calledFunctionName = calledFunction.toString().replace("<EXTERNAL>::", "");
					}

					if (!functionOfInterestName.equalsIgnoreCase(calledFunctionName)) {
						break;
					}

					final DecompileResults decompileResults = this.decomplib.decompileFunction(function, 60,
							this.monitor);
					final HighFunction hf = decompileResults.getHighFunction();
					final ArrayList<PcodeBlockBasic> al = hf.getBasicBlocks();
					for (final PcodeBlockBasic pcbb : al) {
						final Iterator<PcodeOp> pcodeIter = pcbb.getIterator();
						while (pcodeIter.hasNext()) {
							final PcodeOp pcode = pcodeIter.next();
							final int opCode = pcode.getOpcode();
							if (opCode == 7) {
								for (final Varnode input : pcode.getInputs()) {
									if (input.getAddress().equals(calledFunction.getEntryPoint())) {
										final AddressSet addressSet = new AddressSet(pcode.getSeqnum().getTarget());
										results.put(addressSet, function.getName());
									}
								}
							}
						}
					}

				}

			}
		});

		return results;
	}

	public void printToConsole(final Map<AddressSetView, String> results) {
		final PluginTool tool = this.state.getTool();
		final String category = "Vulnerable Function";
		final String comment = "Vulnerable Function Detected";

		for (final Entry<AddressSetView, String> entry : results.entrySet()) {
			final CompoundCmd cmd = new CompoundCmd("Set Note Bookmark");
			final AddressSetView addr = entry.getKey();

			if (addr != null) {
				cmd.add(new BookmarkDeleteCmd(addr, BookmarkType.NOTE));
				cmd.add(new BookmarkEditCmd(addr, BookmarkType.NOTE, category, comment));
			}

			tool.execute(cmd, this.currentProgram);
		}

	}

	/**
	 * Run.
	 *
	 * @throws Exception the exception
	 */
	@Override
	public void run() throws Exception {
		this.decomplib = setUpDecompiler(this.currentProgram);
		if (!this.decomplib.openProgram(this.currentProgram)) {
			printf("Decompiler error: %s\n", this.decomplib.getLastMessage());
		} else {
			final Map<AddressSetView, String> results = getFunctions();
			printToConsole(results);
		}

	}
}
