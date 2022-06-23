
//@keybinding
//@menupath
//@toolbar

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
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
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

/**
 * The Class ClangTokenGenerator.
 */
public class InsecureFunctionFinder extends GhidraScript {

	private DecompInterface decomplib;
	private final List<String> functionsOfInterest = Arrays.asList("printf", "atoi", "atol", "atoll", "gets", "strcat",
			"memcpy", "strcpy", "sprintf", "system", "exec", "strncpy", "vsprintf", "strlen");

	private class InsecureFunctionDetails {
		private Function function;
		private AddressSetView addressSetView;
		private String functionOfInterestName;

		public InsecureFunctionDetails(final Function function, final AddressSetView addressSetView,
				final String functionOfInterestName) {
			this.function = function;
			this.addressSetView = addressSetView;
			this.setFunctionOfInterestName(functionOfInterestName);
		}

		public Function getFunction() {
			return this.function;
		}

		public void setFunction(final Function function) {
			this.function = function;
		}

		public AddressSetView getAddressSetView() {
			return this.addressSetView;
		}

		public void setAddressSetView(final AddressSetView addressSetView) {
			this.addressSetView = addressSetView;
		}

		public String getFunctionOfInterestName() {
			return this.functionOfInterestName;
		}

		public void setFunctionOfInterestName(final String functionOfInterestName) {
			this.functionOfInterestName = functionOfInterestName;
		}

	}

	/**
	 * Decompile function.
	 *
	 * @param function the function to decompile.
	 * @return the high function of the decompiled function.
	 */
	public HighFunction decompileFunction(final Function function) {
		HighFunction highFunction = null;

		try {
			final DecompileResults decompiledResults = this.decomplib.decompileFunction(function,
					this.decomplib.getOptions().getDefaultTimeout(), getMonitor());
			highFunction = decompiledResults.getHighFunction();
		} catch (final Exception exc) {
			printf("EXCEPTION IN DECOMPILATION!\n");
			exc.printStackTrace();
		}

		return highFunction;
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

	public boolean checkFunctionName(final String calledFunctionName, final String functionOfInterestName) {
		String modifiedCalledFunctionName = calledFunctionName;
		if (calledFunctionName.contains("EXTERNAL")) {
			modifiedCalledFunctionName = calledFunctionName.replace("<EXTERNAL>::", "");
		}

		return !functionOfInterestName.equalsIgnoreCase(modifiedCalledFunctionName);
	}

	public void processPcode(final List<InsecureFunctionDetails> results, final PcodeOp pcode,
			final Function calledFunction, final Function function, final String functionOfInterestName) {
		final int opCode = pcode.getOpcode();
		if (opCode == 7) {
			for (final Varnode input : pcode.getInputs()) {
				if (input.getAddress().equals(calledFunction.getEntryPoint())) {
					final AddressSet addressSet = new AddressSet(pcode.getSeqnum().getTarget());
					results.add(new InsecureFunctionDetails(function, addressSet, functionOfInterestName));
				}
			}
		}
	}

	public void processSymbol(final Symbol symbol, final FunctionManager functionManager,
			final List<InsecureFunctionDetails> results) {

		final Function function = functionManager.getFunctionAt(symbol.getAddress());
		if (function == null || function.toString().contains("EXTERNAL")) {
			return;
		}

		final Set<Function> calledFunctions = function.getCalledFunctions(this.monitor);

		// iterate looking for functions of interest being called.
		for (final String functionOfInterestName : this.functionsOfInterest) {
			for (final Function calledFunction : calledFunctions) {

				if (checkFunctionName(calledFunction.toString(), functionOfInterestName)) {
					break;
				}

				final HighFunction highFunction = decompileFunction(function);
				final ArrayList<PcodeBlockBasic> basicBlocks = highFunction.getBasicBlocks();

				for (final PcodeBlockBasic pcodeBlockBasic : basicBlocks) {
					final Iterator<PcodeOp> pcodeIter = pcodeBlockBasic.getIterator();
					while (pcodeIter.hasNext()) {
						final PcodeOp pcode = pcodeIter.next();
						processPcode(results, pcode, calledFunction, function, functionOfInterestName);
					}
				}

			}

		}
	}

	public List<InsecureFunctionDetails> getFunctions() {
		final SymbolIterator symbolIter = this.currentProgram.getSymbolTable().getAllSymbols(false);
		final FunctionManager functionManager = this.getCurrentProgram().getFunctionManager();
		final ArrayList<InsecureFunctionDetails> results = new ArrayList<>();

		// process each symbol
		symbolIter.forEachRemaining(symbol -> {
			processSymbol(symbol, functionManager, results);
		});

		return results;
	}

	
	public void printToConsole(final List<InsecureFunctionFinder.InsecureFunctionDetails> results) {
		final PluginTool tool = this.state.getTool();
		final String category = "Insecure Function";
		final String commentFormat = "Insecure Function %s Detected";

		// add each insecure function detected to bookmarks
		for (final InsecureFunctionDetails vulnFunctionDetails : results) {
			final CompoundCmd cmd = new CompoundCmd("Set Note Bookmark");
			final AddressSetView addr = vulnFunctionDetails.getAddressSetView();
			final String comment = String.format(commentFormat, vulnFunctionDetails.getFunctionOfInterestName().toUpperCase());

			if (addr != null) {
				cmd.add(new BookmarkDeleteCmd(addr, BookmarkType.WARNING));
				cmd.add(new BookmarkEditCmd(addr, BookmarkType.WARNING, category, comment));
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
			final List<InsecureFunctionFinder.InsecureFunctionDetails> results = getFunctions();
			printToConsole(results);
		}

	}
}
