#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <expr.hpp>
#include <frame.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <name.hpp>

#pragma warning (disable:4273)

#include "function_analyzer.h"
#include "loop_detection.h"
/////////////////////////////////////////////////////////////////////////////////////////
// _ida_init()
//
// IDA will call this function only once.
// If this function returns PLUGIN_SKIP, IDA will never load it again.
// If this function returns PLUGIN_OK, IDA will unload the plugin but
// remember that the plugin agreed to work with the database.
// The plugin will be loaded again if the user invokes it by
// pressing the hot key or by selecting it from the menu.
// After the second load, the plugin will stay in memory.
// If this function returns PLUGIN_KEEP, IDA will keep the plugin
// in memory.
//
// arguments: none.
// returns:   plugin status.
//

int _ida_init (void)
{
    // this plug-in only works with metapc (x86) CPU types.
    if(strcmp(inf.procName, "metapc") != 0)
    {
        msg("[!] Detected an incompatible non-metapc CPU type: %s\n", inf.procName);
        return PLUGIN_SKIP;
    }

    return PLUGIN_OK;
}


/////////////////////////////////////////////////////////////////////////////////////////
// _ida_run()
//
// the run function is called when the user activates the plugin. this is the main
// function of the plugin.
//
// arguments: arg - the input argument. it can be specified in the
//                  plugins.cfg file. the default is zero.
// returns:   none.
//

void _ida_run (int arg)
{


loop_detection * ld;
int fid = 0;
int i = 0;
 const char dialog_format [] =
        "STARTITEM 0\n"
        "Loop Detection\n"
        "Loop Options\n\n"
        "Loop Output Options:\n"
            "           <Graph Loop:C>\n<Highlight Function calls:C>>\n"
			"           <Output Stack Information:C>\n<Highlight Code:C>>\n"
			"           <Verbose Output:C>\n<Auto Commenting:C>>\n"
			"           <All Loops Highlight Functions:C>\n<All Loops Code Highlight:C>>\n\n\n"
		"Detection Options:\n"
			"           <Natural Loops Only:C> <Recursive Function Calls:C>>\n\n\n"
        "\n\n";
 unsigned short graph_loop				= 0x0;
 unsigned short highlight_function		= 0x0;
 unsigned short output_stack			= 0x0;
 unsigned short highlight_code			= 0x0;
 unsigned short natural_loops			= 0x0;
 unsigned short recursive_function		= 0x0;
 unsigned short verbose_output			= 0x0;
   
 if ((fid = get_func_num(get_screen_ea())) == -1)
    {
        warning("Current screen effective address:\n\n"
                "          0x%08x\n\n"
                "does not lie within a known function.",
                get_screen_ea());
        return;
    }

    // present the user with the dialog box.
    if (!AskUsingForm_c(dialog_format, &graph_loop,      &output_stack, &highlight_function,  
                                       &highlight_code, &verbose_output, &natural_loops, &recursive_function))
        return;
	ld = new loop_detection(fid);

	//
	// Setup our grapher
	//
	ld->set_manhattan_edges(true);
	ld->set_splines(false);
	ld->set_layout_algorithm("mindepthslow");
	ld->set_finetuning(true);
	ld->set_strip_comments(false);


	switch(graph_loop)
	{
	case 1:
		ld->set_graph(1);
		break;
	case 2:
		ld->set_higlight_function(1);
		break;
	case 3:
		ld->set_graph(1);
		ld->set_higlight_function(1);
		break;
	
	}
	switch(output_stack)
	{
	case 1:
		ld->set_output_stack(1);
		break;
	case 2:
		ld->set_highlight_code(1);
		break;
	case 3:
		ld->set_highlight_code(1);
		ld->set_output_stack(1);
	break;


	}
	switch(highlight_code)
	{
	case 1:
		ld->set_natural_loops(1);
		break;
	case 2:
		ld->set_recursive_function(1);
		break;
	case 3:
		ld->set_recursive_function(1);
		ld->set_natural_loops(1);
		break;

	}
	switch(highlight_function)
	{
	case 1:
		ld->set_verbose_output(1);
		break;
	case 2:
		ld->set_auto_comment(1);
		break;
	case 3:
		ld->set_auto_comment(1);
		ld->set_verbose_output(1);
		break;

	}
	switch(highlight_code)
	{
	case 1:
	{
		
		delete ld;

		msg("Analyzing %d functions\n", get_func_qty() );
		while(i < get_func_qty() )
		{
	
			
			ld = new loop_detection( getn_func(i) );//getn_func( 91 ) );
			if(highlight_function == 1 || highlight_function == 3)
				ld->set_verbose_output(1);

			ld->set_higlight_function(1);
			ld->run_analysis();
			
			delete ld;
			i++;

		}//end while
		msg("Done...\n");
		break;
	}
	case 2:
	{	
		delete ld;
		while(i < get_func_qty() )
		{
	//		msg("ID: %d\n", i);
			
			ld = new loop_detection( getn_func(i) );//getn_func( 91 ) );
			ld->set_highlight_code(1);
			ld->run_analysis();
			msg("looking in function num %d 0x%08x\n", i, ld->first_ea() );
			delete ld;
			i++;

		}//end while
		msg("Done...\n");
		break;
	}
	
	}



	if(!highlight_code)
		ld->run_analysis();

	


	


}


/////////////////////////////////////////////////////////////////////////////////////////
// _ida_term()
//
// IDA will call this function when the user asks to exit. this function will not be
// called in the case of emergency exists. usually this callback is empty.
//
// arguments: none.
// returns:   none.
//

void _ida_term (void)
{
}


// include the data structures that describe the plugin to IDA.
#include "plugin_info.h"
