// loop_detection.cpp: implementation of the loop_detection class.
//
//////////////////////////////////////////////////////////////////////

#include "loop_detection.h"
//#include "function_analyzer.h"
#include "color_palette.h"
#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <expr.hpp>
#include <frame.hpp>
#include <gdl.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <md5.h>
#include <name.hpp>
#include <ua.hpp>
#include <struct.hpp>

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////////////////
// loop_detection()
//
// inititalizes the base class. And this instance
//
// arguments: fid - function id.
// returns:   none
//
loop_detection::loop_detection(int fid) : function_analyzer(fid)
{
	constructor();
}

/////////////////////////////////////////////////////////////////////////////////////////
// loop_detection()
//
// inititalizes the base class. And this instance
//
// arguments: ea - ea of the function.
// returns:   none
//
loop_detection::loop_detection(ea_t ea) : function_analyzer(ea)
{
	constructor();
}

/////////////////////////////////////////////////////////////////////////////////////////
// loop_detection()
//
// inititalizes the base class. And this instance
//
// arguments: ea - ea of the function.
// returns:   none
//
loop_detection::loop_detection(func_t * fptr) : function_analyzer(fptr)
{
	constructor();
}

/////////////////////////////////////////////////////////////////////////////////////////
// loop_detection()
//
// destructor
//
// arguments: none
// returns:   none
//
loop_detection::~loop_detection() 
{

}



/////////////////////////////////////////////////////////////////////////////////////////
// find_loop()
//
// runs the analysis on the current function.
//
// arguments: ea_t master - master would be the entry point of the node 
//			  ea_t slave - is the node that links back to the head
// returns:   none.
//
int loop_detection::find_loop(ea_t master, ea_t slave)
{


	ea_t ea;
	ea_t master_src = find_src(master);
	ea_t slave_src = find_src(slave);
	ea_t frag;
	int i = 0;
	int bFrag = 0;
	int num_ref = get_num_references_to(slave);

	//
	// if our src is BADADDR then leave
	//
	if(slave_src == BADADDR) return 0;

	if(master_src == BADADDR) return 0;

	if(get_first_fcref_from(master_src) == master)
		return 1;
	//
	// To be a loop we need a back edge so we check to make sure our slave 
	// references our master then we make sure that our master can reach our slave
	// so that we can verify there is a loop
	//
	if(is_reference_to(master, slave_src) && is_path_to(master,slave)) 
	{
		//msg("0x%08x is referenced by 0x%08x\n", master, slave_src);
		return 1;
	}

	return 0;
}




/////////////////////////////////////////////////////////////////////////////////////////
// run_analysis()
//
// a virtual function so that we can still call our base class run_analysis
// this function does the analysis of loops and parses the users input requests
//
// arguments: none
// returns:   none
//
void loop_detection::run_analysis()
{


	//
	//run analysis of function_analyzer first
	//
	function_analyzer::run_analysis();
	//
	// setup our entry point variable
	//
	entry_point = first_ea();

	//
	//find all the loops in the function if
	// natural loops wasn't selected
	//


	if(!get_natural_loops() )
		find_loops();
	else
		find_natural_loops();


	if(get_highlight_function() )
		highlight_functions();

	if(get_highlight_code() )
		highlight_codes();

	if(get_recursive_function() )
		find_recursive_functions();

	//
	//do we graph the results?
	//
	if(get_graph())
			graph();


}

/////////////////////////////////////////////////////////////////////////////////////////
// find_natural_loop()
//
// will look for only natural loops 
//
// arguments: master - the node that should dominate 
//			  slave  - the node that is dominated by master and references master
// returns:   true or false
//
int loop_detection::find_natural_loop(ea_t master, ea_t slave)
{
	
	ea_t master_src = find_src(master);
	ea_t slave_src = find_src(slave);

	//
	// Does master dominate slave?
	//
	if(is_path_to(entry_point,slave,master) )
	{
		//
		// Master dominates slaves now can we get from
		//
		if( is_reference_to(master, slave_src) )
		{
			return 1;
		}

	}
	else
		return 0;
	

}

/////////////////////////////////////////////////////////////////////////////////////////
// is_path_to()
//
// tries to find a path from -> to verifying the flow of the program can hit to
//
// arguments: from - the ea of the start address
//			  to   - the ea of the destination
// returns:   true or false
//
int loop_detection::is_path_to(ea_t from, ea_t to)
{

	ea_t from_src = find_src(from);
	ea_t to_src	  = find_src(to);
	
	ea_t next;
	ea_t fcref;

	char disasm_buf[512];

	int result = 0;

	
	//
	// Check if our edges are valid if not exit
	//
	if(from_src == BADADDR || to_src == BADADDR)
	{
#ifdef DEBUG_LOOP
		msg("Could not find a src from 0x%08x\n", from);
#endif
		return 0;

	}
	//
	// make sure our "start" and "end" are valid
	//
	if(from == BADADDR || to == BADADDR) 
	{
#ifdef DEBUG_LOOP
		msg("from 0x%08x or to 0x%08x is BADADDR\n", from, to);
#endif
		return 0;
	}

	//
	// if from_src is a reference to our destination we got to our goal
	//
	if(is_reference_to(to, from_src) ) 
	{
#ifdef DEBUG_LOOP
		msg("is_reference_to(0x%08x, 0x%08x)\n", to, from_src);
#endif
		add_loop(to);
		return 1;
	}
	//get the jump ea 
	fcref = get_first_fcref_from(from_src);
	//get the next instruction
	next = next_ea(from_src);
#ifdef DEBUG_LOOP
	msg("FCREF 0x%08x NEXT 0x%08x to 0x%08x from 0x%08x\n", fcref, next, to, from);
#endif
	//kill infinite loop
	if(fcref == from) 
	{
#ifdef DEBUG_LOOP
		msg("fcref 0x%08x is equal to from 0x%08x\n",fcref,from);
#endif
		return 0;
	}


	//we got to our goal
	if(fcref == to) 
	{
#ifdef DEBUG_LOOP
		msg("fcref 0x%08x is equal to 0x%08x our goal\n",fcref,to);
#endif
		add_loop(to);
		return 1;
	}
	//we got to our goal
	if(next == to) 
	{
#ifdef DEBUG_LOOP
		msg("next 0x%08x equal to  0x%08x\n", next, to);
#endif
		add_loop(to);
		return 1;
	}
	//get instruction
	ua_mnem(from_src, disasm_buf, 512);
	tag_remove(disasm_buf, disasm_buf, 512);	
	if(strstr(disasm_buf,"j") != NULL)
	{
#ifdef DEBUG_LOOP
		msg("J** instruction\n");
#endif
		//makes sure we don't look at nodes that are exit
		if(find_src(fcref) == BADADDR) 
		{
#ifdef DEBUG_LOOP
			msg("could not find a src for fcref 0x%08x\n", fcref);
#endif
			result = is_path_to(fcref, to);
			if(result)
			{
				add_loop(fcref);
				add_loop(to);
				return 1;
			}
		}
#ifdef DEBUG_LOOP
		msg("No path from 0x%08x to 0x%08x\n", fcref, to);
#endif
		result = is_path_to(next, to);
		if(result)
		{
#ifdef DEBUG_LOOP
			msg("Took next and found a path\n");
#endif
			add_loop(next);
			add_loop(to);
			return 1;
		}
		

	}
	else
		return is_path_to(next, to);


	
	return 0;
}
/////////////////////////////////////////////////////////////////////////////////////////
// is_fragmented_head()
//
// 
//
// arguments: 
// returns:   none
//
ea_t loop_detection::is_fragmented_head(ea_t head)
{

	ea_t to = get_first_cref_to(head);

	while(head != BADADDR)
	{
			
		if(find_src(to) == BADADDR) return to;

		to = get_next_cref_to(head, to);
	}
	return BADADDR;
}
/////////////////////////////////////////////////////////////////////////////////////////
// is_valid_node()
//
// makes sure it is a valid ea/node by checking if there is an instruction at the location
//
// arguments: ea - ea of node to check.
// returns:   true or false
//
int loop_detection::is_valid_node(ea_t ea)
{
char disasm_buf[512];
	memset(disasm_buf,0,sizeof disasm_buf);
	ua_mnem(ea, disasm_buf, 512);
	tag_remove(disasm_buf, disasm_buf, 512);	
	
	if(strlen(disasm_buf) <= 1) return 0;
	return 1;
}

/////////////////////////////////////////////////////////////////////////////////////////
// is_path_to() - overloaded
//
// checks to see if there is a path from "start" to "destination but in this overloaded 
// function. We specify a node to avoid. This allows us to verify if we can't get to our desitnation
// avoiding a node then that node dominates the destination
//
// arguments: fid - function id.
// returns:   none
//
int loop_detection::is_path_to(ea_t from, ea_t to, ea_t avoid)
{

	ea_t from_src = find_src(from);
	ea_t to_src	  = find_src(to);
	
	ea_t next;
	ea_t fcref;

	char disasm_buf[512];

	int result = 0;

	if(from_src == BADADDR)
	{
#ifdef DEBUG_DOM
		msg("Could not find a src from 0x%08x\n", from);
#endif
		return 0;

	}
	if(from == BADADDR || to == BADADDR) 
	{
#ifdef DEBUG_DOM
		msg("from 0x%08x or to 0x%08x is BADADDR\n", from, to);
#endif
		return 0;
	}
	
	if(to == avoid)
	{
#ifdef DEBUG_DOM
		msg("to 0x%08x is == to avoid 0x%08x ", to, avoid);
#endif
		return 0;
	}
	if(from == avoid)
	{
#ifdef DEBUG_DOM
		msg("from 0x%08x is == to avoid 0x%08x ", from, avoid);
#endif
		return 0;
	}
	if(from_src == avoid)
	{
#ifdef DEBUG_DOM
		msg("from src 0x%08x is == to avoid 0x%08x ", from_src, avoid);
#endif
		return 0;
	}

	if(is_reference_to(to, from_src) ) 
	{
#ifdef DEBUG_DOM
		msg("is_reference_to(0x%08x, 0x%08x)\n", to, from_src);
#endif
		return 1;
	}

	fcref = get_first_fcref_from(from_src);
	next = next_ea(from_src);
#ifdef DEBUG_DOM
	msg("FCREF 0x%08x NEXT 0x%08x to 0x%08x from 0x%08x\n", fcref, next, to, from);
#endif
	//kill infinite loop
	if(fcref == from) 
	{
#ifdef DEBUG_DOM
		msg("fcref 0x%08x is equal to from 0x%08x\n",fcref,from);
#endif
		return 0;
	}

	if(fcref== avoid)
	{
#ifdef DEBUG_DOM
		msg("fcref 0x%08x is == to avoid 0x%08x ", fcref, avoid);
#endif
		return 0;
	}
	
	if(next == avoid)
	{
#ifdef DEBUG_DOM
		msg("next 0x%08x is == to avoid 0x%08x ", next, avoid);
#endif
		return 0;
	}

	//we got to our goal
	if(fcref == to) 
	{
#ifdef DEBUG_DOM
		msg("fcref 0x%08x is equal to 0x%08x our goal\n",fcref,to);
#endif
		return 1;
	}
	//we got to our goal
	if(next == to) 
	{
#ifdef DEBUG_DOM
		msg("next 0x%08x equal to  0x%08x\n", next, to);
#endif
		return 1;
	}
	ua_mnem(from_src, disasm_buf, 512);
	tag_remove(disasm_buf, disasm_buf, 512);	
	if(strstr(disasm_buf,"j") != NULL)
	{
#ifdef DEBUG_DOM
		msg("J** instruction\n");
#endif
		//makes sure we don't look at nodes that are exit
		if(find_src(fcref) == BADADDR) 
		{
#ifdef DEBUG_DOM
			msg("could not find a src for fcref 0x%08x\n", fcref);
#endif
			result = is_path_to(fcref, to, avoid);
			if(result)
				return 1;
		}
#ifdef DEBUG_DOM
		msg("No path from 0x%08x to 0x%08x\n", fcref, to);
#endif
		result = is_path_to(next, to, avoid);
		if(result)
		{
#ifdef DEBUG_DOM
			msg("Took next and found a path\n");
#endif
			return 1;
		}
		//msg("No path from 0x%08x to 0x%08x\n", next, to);
		//return 0;

	}
	else
		return is_path_to(next, to, avoid);


	
	return 0;
}
/////////////////////////////////////////////////////////////////////////////////////////
// add_loop()
//
// adds ea to the list of nodes
//
// arguments: ea - adds ea to loop.
// returns:   true or false.
//
int loop_detection::add_loop(ea_t ea)
{
  int i;

    // search for an existing node.
    for (i = 1; i <= num_loops; i++)
        if (loops[i] == ea)
            return FALSE;

    #ifdef FA_DEBUG
        msg("FA_DEBUG> add_loop(%08x)\n", ea);
    #endif

    // no existing node was found. ensure we have space for the new node
    // we are about to add.
    if ((num_loops + 1) % 10 == 0)
        loops = (ea_t *) qrealloc(loops, (num_loops + 10 + 1) * sizeof(ea_t));

    // record the new node.
    num_loops++;
    loops[num_loops] = ea;

    return TRUE;
}
/////////////////////////////////////////////////////////////////////////////////////////
// is_loop()
//
// checks to see if the ea is in our loop
//
// arguments: ea - ea to check.
// returns:   true or false.
//
int loop_detection::is_loop(ea_t ea)
{
  int i;

    // search for an existing node.
    for (i = 1; i <= num_loops; i++)
        if (loops[i] == ea)
            return TRUE;

    return FALSE;
}
/////////////////////////////////////////////////////////////////////////////////////////
// add_start_loop()
//
// adds ea to the list of start nodes
//
// arguments: ea - adds ea to list.
// returns:   true or false.
//
int loop_detection::add_start_loop(ea_t ea)
{
  int i;

    // search for an existing node.
    for (i = 1; i <= num_start_loops; i++)
        if (start_loops[i] == ea)
            return FALSE;

    #ifdef FA_DEBUG
        msg("FA_DEBUG> add_start_loop(%08x)\n", ea);
    #endif

    // no existing node was found. ensure we have space for the new node
    // we are about to add.
    if ((num_start_loops + 1) % 10 == 0)
        start_loops = (ea_t *) qrealloc(start_loops, (num_start_loops + 10 + 1) * sizeof(ea_t));

    // record the new node.
    num_start_loops++;
    start_loops[num_start_loops] = ea;

    return TRUE;
}

/////////////////////////////////////////////////////////////////////////////////////////
// add_end_loop()
//
// adds ea to the list of end nodes
//
// arguments: ea - adds ea to list.
// returns:   true or false.
//
int loop_detection::add_end_loop(ea_t ea)
{
  int i;

    // search for an existing node.
    for (i = 1; i <= num_end_loops; i++)
        if (end_loops[i] == ea)
            return FALSE;

    #ifdef FA_DEBUG
        msg("FA_DEBUG> add_end_loop(%08x)\n", ea);
    #endif

    // no existing node was found. ensure we have space for the new node
    // we are about to add.
    if ((num_end_loops + 1) % 10 == 0)
        end_loops = (ea_t *) qrealloc(end_loops, (num_end_loops + 10 + 1) * sizeof(ea_t));

    // record the new node.
    num_end_loops++;
    end_loops[num_end_loops] = ea;

    return TRUE;
}

/////////////////////////////////////////////////////////////////////////////////////////
// is_start_loop()
//
// checks to see if the node starts a loop.
//
// arguments: ea - to check to see if the node is in our list.
// returns:   true or false.
//
int loop_detection::is_start_loop(ea_t ea)
{
  int i;

    // search for an existing node.
    for (i = 1; i <= num_start_loops; i++)
        if (start_loops[i] == ea)
            return TRUE;

    return FALSE;
}

/////////////////////////////////////////////////////////////////////////////////////////
// is_end_loop()
//
// checks to see if the node ends a loop.
//
// arguments: ea - to check to see if the node is in our list.
// returns:   true or false.
//
int loop_detection::is_end_loop(ea_t ea)
{
  int i;

    // search for an existing node.
    for (i = 1; i <= num_end_loops; i++)
        if (end_loops[i] == ea)
            return TRUE;

    return FALSE;
}





/////////////////////////////////////////////////////////////////////////////////////////
// graph()
//
// generate and display a graph for this routine.
//
// arguments: none.
// returns:   none.
//

void loop_detection::graph (void)
{
    FILE *fp = NULL;
    char disasm_buf[FA_DISASM_BUFLEN];
    char tmp_buf   [FA_DISASM_BUFLEN];
    char path[1024];
    char *tmp, *dis,*name;
    int  i;
	int  t = 0;
	int idx = 0;
    ea_t ea;
    ea_t fcref;
    ea_t src;
	ea_t endOffset;
	ea_t beginOffset;
	struc_t * struc = get_frame(get_func(first_ea() ) );
	member_t* member;
	funcx * fx = new funcx(get_func(first_ea() ) );
    
	// generate a random file name in the temp directory to store our graph.
    qtmpnam(path);

    // open the output file.
    if ((fp = qfopen(path, "wb")) == NULL)
    {
        msg("graph> Failed to open %s for writing.\n", path);
        return;
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    // graph header.
    //
    qfprintf(fp, "graph:\n"
                 "{\n"
                 "\ttitle:                \"graph of %08x\"\n"
                 "\tmanhattan_edges:      %s\n"
                 "\tsplines:              %s\n"
                 "\tfinetuning:           %s\n"
                 "\tlayoutalgorithm:      %s\n"
                 "\tlayout_downfactor:    %d\n"
                 "\txlspace:              %d\n"
                 "\txspace:               %d\n"
                 "\tcolor:                %s\n"
                 "\n"FA_COLOR_PALETTE"\n",
                 nodes[1],
                 manhattan_edges ? "yes" : "no",
                 splines         ? "yes" : "no",
                 finetuning      ? "yes" : "no",
                 layout_algorithm,
                 layout_downfactor,
                 xlspace,
                 xspace,
                 color);

    ///////////////////////////////////////////////////////////////////////////////////////////////
    // graph nodes.
    //

    // graph the nodes.
    for (i = 1; i <= num_nodes; i++)
    {

	
        // open the node.
        qfprintf(fp, "\tnode: { title: \"%08x\" label: \""FA_COLOR_LABEL"%08x:", nodes[i], nodes[i]);
		if(get_output_stack() )
		{
			if(nodes[i] == first_ea())
			{
				struc = get_frame( get_func(first_ea()) );
		
				while(t  != struc->memqty )
				{

						
						endOffset = struc->members[t].soff;
						
						
						if(t == struc->memqty-1)
						{
							
							beginOffset = struc->members[ t ].eoff;
						}
						else
							beginOffset = struc->members[ t + 1 ].soff;

						size = ( beginOffset - endOffset ) ;
						
						name = get_member_name(struc->members[t].id);
						
						if(struc->members[t].soff < (fx->GetReturnAddressSize() + fx->GetLocalVariableSize() + fx->GetSavedRegsSize()) )
							qfprintf(fp, "\n"FA_COLOR_ADDRESS"%08x Local Variable: %s[%d]", first_ea() , name, size);
						else
							qfprintf(fp, "\n"FA_COLOR_ADDRESS"%08x Function Arguement: %s[%d]", first_ea() , name, size);
							
						t++;

				}//end whhile
			}
		}
	
        // insert the disassembly of this node into the label.
        for (ea = nodes[i]; ea != BADADDR; ea = next_ea(ea))
        {
            // clear our disassembly buffers.
            memset(disasm_buf, 0, sizeof(disasm_buf));
            memset(tmp_buf,    0, sizeof(tmp_buf));

            // generate the disassembly for the current effective address.
            generate_disasm_line(ea, tmp_buf, FA_DISASM_BUFLEN);

            // strip out comments from the generated disassembly.
            // comments start with a semi-colon ';'.
            if (strip_comments)
            {
                if ((tmp = strchr(tmp_buf, ';')) != NULL)
                {
                    // cut through all the whitespace.
                    for(tmp--; *tmp == ' '; tmp--)
                        *tmp = 0x00;
                }
            }
            // replace all double quotes (") with single quotes (').
            else
            {
                while ((tmp = strchr(tmp_buf, '"')) != NULL)
                    *tmp = '\'';
            }

            // convert IDA coloring to wingraph32 compatible format.
            for (tmp = tmp_buf, dis = disasm_buf; tmp <= tmp_buf + strlen(tmp_buf); tmp++)
            {
                // escape character on. (convert format)
                if (*tmp == COLOR_ON)
                {
                    // go to the next character.
                    tmp++;

                    switch (*tmp)
                    {
                        case COLOR_DEFAULT:   strcat(disasm_buf, FA_COLOR_DEFAULT  ); break;
                        case COLOR_REGCMT:    strcat(disasm_buf, FA_COLOR_REGCMT   ); break;
                        case COLOR_RPTCMT:    strcat(disasm_buf, FA_COLOR_RPTCMT   ); break;
                        case COLOR_AUTOCMT:   strcat(disasm_buf, FA_COLOR_AUTOCMT  ); break;
                        case COLOR_INSN:      strcat(disasm_buf, FA_COLOR_INSN     ); break;
                        case COLOR_DATNAME:   strcat(disasm_buf, FA_COLOR_DATNAME  ); break;
                        case COLOR_DNAME:     strcat(disasm_buf, FA_COLOR_DNAME    ); break;
                        case COLOR_DEMNAME:   strcat(disasm_buf, FA_COLOR_DEMNAME  ); break;
                        case COLOR_SYMBOL:    strcat(disasm_buf, FA_COLOR_SYMBOL   ); break;
                        case COLOR_CHAR:      strcat(disasm_buf, FA_COLOR_CHAR     ); break;
                        case COLOR_STRING:    strcat(disasm_buf, FA_COLOR_STRING   ); break;
                        case COLOR_NUMBER:    strcat(disasm_buf, FA_COLOR_NUMBER   ); break;
                        case COLOR_VOIDOP:    strcat(disasm_buf, FA_COLOR_VOIDOP   ); break;
                        case COLOR_CREF:      strcat(disasm_buf, FA_COLOR_CREF     ); break;
                        case COLOR_DREF:      strcat(disasm_buf, FA_COLOR_DREF     ); break;
                        case COLOR_CREFTAIL:  strcat(disasm_buf, FA_COLOR_CREFTAIL ); break;
                        case COLOR_DREFTAIL:  strcat(disasm_buf, FA_COLOR_DREFTAIL ); break;
                        case COLOR_ERROR:     strcat(disasm_buf, FA_COLOR_ERROR    ); break;
                        case COLOR_PREFIX:    strcat(disasm_buf, FA_COLOR_PREFIX   ); break;
                        case COLOR_BINPREF:   strcat(disasm_buf, FA_COLOR_BINPREF  ); break;
                        case COLOR_EXTRA:     strcat(disasm_buf, FA_COLOR_EXTRA    ); break;
                        case COLOR_ALTOP:     strcat(disasm_buf, FA_COLOR_ALTOP    ); break;
                        case COLOR_HIDNAME:   strcat(disasm_buf, FA_COLOR_HIDNAME  ); break;
                        case COLOR_LIBNAME:   strcat(disasm_buf, FA_COLOR_LIBNAME  ); break;
                        case COLOR_LOCNAME:   strcat(disasm_buf, FA_COLOR_LOCNAME  ); break;
                        case COLOR_CODNAME:   strcat(disasm_buf, FA_COLOR_CODNAME  ); break;
                        case COLOR_ASMDIR:    strcat(disasm_buf, FA_COLOR_ASMDIR   ); break;
                        case COLOR_MACRO:     strcat(disasm_buf, FA_COLOR_MACRO    ); break;
                        case COLOR_DSTR:      strcat(disasm_buf, FA_COLOR_DSTR     ); break;
                        case COLOR_DCHAR:     strcat(disasm_buf, FA_COLOR_DCHAR    ); break;
                        case COLOR_DNUM:      strcat(disasm_buf, FA_COLOR_DNUM     ); break;
                        case COLOR_KEYWORD:   strcat(disasm_buf, FA_COLOR_KEYWORD  ); break;
                        case COLOR_REG:       strcat(disasm_buf, FA_COLOR_REG      ); break;
                        case COLOR_IMPNAME:   strcat(disasm_buf, FA_COLOR_IMPNAME  ); break;
                        case COLOR_SEGNAME:   strcat(disasm_buf, FA_COLOR_SEGNAME  ); break;
                        case COLOR_UNKNAME:   strcat(disasm_buf, FA_COLOR_UNKNAME  ); break;
                        case COLOR_CNAME:     strcat(disasm_buf, FA_COLOR_CNAME    ); break;
                        case COLOR_UNAME:     strcat(disasm_buf, FA_COLOR_UNAME    ); break;
                        case COLOR_COLLAPSED: strcat(disasm_buf, FA_COLOR_COLLAPSED); break;
                        case COLOR_FG_MAX:
                            strcat(disasm_buf, FA_COLOR_FG_MAX);
                            // NOTE - generate_disasm_line returns locational references in the form:
                            //            ????????loc_????????
                            ///       where ??????? is the 8 digit 0-padded hexidecimal address of the
                            //        location. the simplest way to deal with this is to simply increment
                            //        past the initial location address (the following +8) thereby only
                            //        leaving the remaining name to be used by our grapher.
                            tmp += 8;
                            break;
                        default:
                            strcat(disasm_buf, FA_COLOR_DEFAULT);
                    }

                    dis += 3;
                }

                // escape character off. (ignore these)
                else if (*tmp == COLOR_OFF)
                    tmp++;

                // quote next character.
                else if (*tmp == COLOR_ESC)
                {
                    // go to the next character.
                    tmp++;

                    // copy the character as a string.
                    _snprintf(disasm_buf, sizeof(disasm_buf) - 1, "%s0x%02x", disasm_buf, *tmp);
                }

                // inverse colors. (ignore these)
                else if (*tmp == COLOR_INV)
                    tmp++;

                else
                {
                    *dis = *tmp;
                    dis++;
                }
            }

            // write this line to the output file.
            qfprintf(fp, "\n"FA_COLOR_ADDRESS"%08x %s", ea, disasm_buf);

            // break if the next instruction is the start of another node.
            if (is_node(next_ea(ea)))
                break;

            // if the current instruction is far off.
            if (ea < ea_start || ea > ea_end)
            {
                memset(disasm_buf, 0, sizeof(disasm_buf));
                disasm(ea, disasm_buf);

                fcref = get_first_fcref_from(ea);

                // break if the current instruction returns back to our original code.
                if (fcref >= ea_start && fcref <= ea_start && strnicmp(disasm_buf, "jmp", 3) == 0)
                    break;

                if (strnicmp(disasm_buf, "ret", 3) == 0)
                    break;
            }
        }

        //
        // select the appropriate color/shape for this node and close it.
        //

		//qfprintf(fp, "");
        // entry point.
        if (nodes[i] == ea_start)
            qfprintf(fp, "\" borderwidth: 7 color: %s }\n", color_node);
		else if(is_start_loop(nodes[i]) )
			qfprintf(fp, "\" borderwidth: 7 bordercolor: green }\n");
		else if(is_end_loop(nodes[i]) )
			qfprintf(fp, "\" borderwidth: 7 bordercolor: red }\n");
		else if(is_loop(nodes[i]) )
			qfprintf(fp, "\" borderwidth: 7 bordercolor: yellow }\n"); 
	
        // far off nodes.
        else if (nodes[i] < ea_start || nodes[i] > ea_end)
            qfprintf(fp, "\" color: %s }\n", color_far_off);

        // regular nodes.
        else
            qfprintf(fp, "\" color: %s }\n", color_node);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    // graph edges.
    //

    // graph all the recorded edges.
    for (i = 1; i <= num_edges; i++)
    {
        // determine the source node by looking backwards until we find the start of a node.
        for (src = edges_src[i]; src != BADADDR; src = prev_visea(src))
            if (is_node(src))
                break;

        qfprintf(fp, "\tedge: { sourcename: \"%08x\" targetname: \"%08x\"", src, edges_dst[i]);

        // find the end of this node, ie: the branching instruction.
        for (fcref = BADADDR, ea = edges_src[i]; fcref == BADADDR; ea = next_ea(ea))
        {
            if ((fcref = get_first_fcref_from(ea)) != BADADDR)
            {
                memset(disasm_buf, 0, sizeof(disasm_buf));
                disasm(ea, disasm_buf);

                // we are looking for a jump.
                if (disasm_buf[0] != 'j')
                    fcref = BADADDR;
            }
        }

        // unconditional jump.
        if (strnicmp(disasm_buf, "jmp", 3) == 0)
            qfprintf(fp, " color: black }\n");
        // conditional jump, true branch.
        else if (fcref == edges_dst[i])
            qfprintf(fp, " color: green }\n");
        // conditional jump, false branch.
        else
            qfprintf(fp, " color: red }\n");
    }

    // graph the implicit edges.
    // these are the edges from one instruction to the next, where the next instruction is the
    // start of a new node.
    // branching / return instructions are ignored here.
    for (ea = first_ea(); ea != BADADDR; ea = next_ea(ea))
    {
        memset(disasm_buf, 0, sizeof(disasm_buf));
        disasm(ea, disasm_buf);

        if (strnicmp(disasm_buf, "ret", 3) == 0)
            continue;

        if (get_first_fcref_from(ea) != BADADDR && disasm_buf[0] == 'j')
            continue;

        if (is_node(next_ea(ea)))
        {
            // determine the source node by looking backwards until we find the start of a node.
            for (src = ea; src != BADADDR; src = prev_visea(src))
                if (is_node(src))
                    break;

            qfprintf(fp, "\tedge: { sourcename: \"%08x\" targetname: \"%08x\" color: blue }\n", src, next_ea(ea));
        }
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    // graph footer.
    //

    qfprintf(fp, "}\n");

    // close the output stream.
    qfclose(fp);

    // display the graph.
    display_gdl(path);
}


void loop_detection::constructor()
{

 graph_loop				= 0;
 highlight_function		= 0;
 output_stack			= 0;
 highlight_code			= 0;
 natural_loops			= 0;
 recursive_function		= 0;
 verbose_output			= 0;
 auto_comment			= 0;

    num_loops		 = 0;
	num_start_loops	 = 0;
	num_end_loops	 = 0;    
	loops		 = (ea_t *) qalloc(10 * sizeof(ea_t));
    start_loops	 = (ea_t *) qalloc(10 * sizeof(ea_t));
    end_loops	 = (ea_t *) qalloc(10 * sizeof(ea_t));
   
}

/////////////////////////////////////////////////////////////////////////////////////////
// find_loops()
//
// is a wrapper function that uses the find_loop function to identify loops within 
// two nodes. This function helps to impelment the algorithm described in the paper.
//
// arguments: none
// returns:   none
//
void loop_detection::find_loops()
{
	int i = 1;
	int t = 1;
	ea_t d;
	ea_t n;
	char comment_line[400];

	//
	//our first for loop
	//
	for(i = 1; i <= num_nodes; i++)
	{
		
		//
		//our nested for loop
		//
		for(t = 1; t <= num_nodes; t++)
		{
			//
			// Check if the node is valid this check
			// makes sure there actual instructions at the ea and
			// that the ea doesn't just contain garbage
			//
			if( is_valid_node(nodes[i]) )
			{
				//
				// Go through the nodes sequentially
				//
				if(nodes[i] <= nodes[t] )
				{
				
					//
					// call find_loop which returns a true or false if it finds
					// a loop or not
					//
					if(find_loop(nodes[i], nodes[t]) )
					{
						//
						// Check if the head is actually fragmented 
						//
						d = is_fragmented_head(nodes[i]);
						n = is_fragmented_head(nodes[t]);
						//
						// head isn't fragmented replace it with the aactual node value
						//
						if(d == BADADDR) 
							d = nodes[i];
						

						//
						// head isn't fragmented replace with actual node value
						//
						if(n == BADADDR)
							n = nodes[t];
						
						//
						// add ea's to our lists
						//
						if(get_auto_comment() )
						{
							qsnprintf(comment_line, 400, "Begining of Loop. Ends at 0x%08x\n", n);
							append_cmt(d,comment_line,false);
							qsnprintf(comment_line, 400, "End of Loop. Begins at 0x%08x\n", d);
							append_cmt(n,comment_line,false);
						}
						add_start_loop(d);
						add_end_loop(n);
						add_loop(d);
						add_loop(n);
						add_loop(nodes[t]);
						add_loop(nodes[i]);
						
						//
						// if our master is actually two nodes in one 
						// this check will add the second node
						//
						if(nodes[i] != get_node(find_src(nodes[i]) ) )
						{
							
							add_loop(get_node(find_src(nodes[i]) ) );
						}
						//
						// Tell the user we found a loop
						//
						//msg("Found Loop: 0x%08x -> 0x%08x\n", d,n);
					}
				}//end if
			}
		}//end for
	}//end for
	
		
	
}


/////////////////////////////////////////////////////////////////////////////////////////
// highlight_functions()
//
// this function will highlight any ea's that have function calls within a loop
//
// arguments: none
// returns:   none
//
void loop_detection::highlight_functions()
{
	int i = 1;
	ea_t ea;
	ea_t loop_begin;
	char instruction[512];
	char func_name[512];
	//
	// go through all our nodes involved in loops
	//
	while( i < num_loops)
	{

		ea = loops[i];
		//
		// set the begining of our loop
		//
		loop_begin = ea;
		//
		// while we are on a valid ea and we aren't where we began
		//
		while(ea != BADADDR && ea != find_src(loop_begin) )
		{
			ua_mnem(ea, instruction, 512);
			tag_remove(instruction, instruction, 512);
			//
			// if the instructino is a call then lets mark it
			//
			if(strstr(instruction,"call") != NULL)
			{
	
				//
				// if the user wants verbose output then tell them in the output window what
				// is going on
				//
				if(get_verbose_output() )
				{
					ua_outop(ea, func_name, 512, 0);
					tag_remove(func_name, func_name, 512);
					msg("Found function %s within a loop at 0x%08x\n",func_name, ea);
				}
				//
				// set the background
				//
				set_item_color(ea, 0x0e);
			}
			ea = next_ea(ea);
		}
		i++;
	}
}


/////////////////////////////////////////////////////////////////////////////////////////
// highlight_codes()
//
// inititalizes the base class. And this instance
//
// arguments: ea - ea of the function.
// returns:   none
//
void loop_detection::highlight_codes()
{
	int i = 1;
	ea_t ea;
	ea_t loop_begin;
	//
	// loop through all our loop nodes
	//
	while( i < num_loops)
	{
				
		ea = loops[i];
		loop_begin = ea;
		//
		// while our ea is valid and we have not reached the begining of our
		// loop node
		//
		while(ea != BADADDR && ea != find_src(loop_begin) )
		{
			//
			// set our background
			//
			set_item_color(ea, 0x0b);
			ea = next_ea(ea);
		}
		i++;
	}
}


/////////////////////////////////////////////////////////////////////////////////////////
// find_recursive_functions()
//
// will attempt to find functions that call themsleves (recursion)
//
// arguments: none
// returns:   none
//
void loop_detection::find_recursive_functions()
{
	ea_t ea = first_ea();
	char instruction[512];
	ea_t fcref;
	ea_t ea_xref;
	//
	// go through whole function
	//
	while(last_ea() != ea)
	{
		ua_mnem(ea, instruction, 512);
		tag_remove(instruction, instruction, 512);
		if(strstr(instruction,"call") != NULL)
		{
			fcref = get_first_fcref_from(ea);
		
				if(fcref == ea )
				{
					//
					// Recursive Function 
					//
					msg("Found Recursive Function at 0x%08x\n", ea);
					append_cmt(ea,"Recursive Function Call",0);

				}
		
		}//end if
		ea = next_ea(ea);
	}

}

/////////////////////////////////////////////////////////////////////////////////////////
// find_natural_loops()
//
// is a wrapper function that uses the find_loop function to identify loops within 
// two nodes
//
// arguments: none
// returns:   none
//
void loop_detection::find_natural_loops()
{
	int i = 1;
	int t = 1;
	ea_t d;
	ea_t n;

	//
	//our first for loop
	//
	for(i = 1; i <= num_nodes; i++)
	{
		
		//
		//our nested for loop
		//
		for(t = 1; t <= num_nodes; t++)
		{
			//
			// Check if the node is valid this check
			// makes sure there actual instructions at the ea and
			// that the ea doesn't just contain garbage
			//
			if( is_valid_node(nodes[i]) )
			{
				//
				// Go through the nodes sequentially
				//
				if(nodes[i] <= nodes[t] )
				{
				
					//
					// call find_loop which returns a true or false if it finds
					// a loop or not
					//
					if(find_natural_loop(nodes[i], nodes[t]) )
					{
						//
						// Check if the head is actually fragmented 
						//
						d = is_fragmented_head(nodes[i]);
						n = is_fragmented_head(nodes[t]);
						//
						// head isn't fragmented replace it with the aactual node value
						//
						if(d == BADADDR) 
							d = nodes[i];
						

						//
						// head isn't fragmented replace with actual node value
						//
						if(n == BADADDR)
							n = nodes[t];
						
						//
						// add ea's to our lists
						//
						add_start_loop(d);
						add_end_loop(n);
						add_loop(d);
						add_loop(n);
						add_loop(nodes[t]);
						add_loop(nodes[i]);
						
						//
						// if our master is actually two nodes in one 
						// this check will add the second node
						//
						if(nodes[i] != get_node(find_src(nodes[i]) ) )
						{
							
							add_loop(get_node(find_src(nodes[i]) ) );
						}
						//
						// Tell the user we found a loop
						//
						//msg("Found Loop: 0x%08x -> 0x%08x\n", d,n);
					}
				}//end if
			}
		}//end for
	}//end for
	
		
}
