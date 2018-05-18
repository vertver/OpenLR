// EngineAPI.cpp: implementation of the CEngineAPI class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "EngineAPI.h"
#include "../xrcdb/xrXRC.h"
#include "XR_IOConsole.h"
#include "xr_ioc_cmd.h"

//#include "securom_api.h"

extern xr_token* vid_quality_token;

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

void __cdecl dummy(void)
{
};
CEngineAPI::CEngineAPI()
{
    hGame = 0;
    hRender = 0;
    hTuner = 0;
    pCreate = 0;
    pDestroy = 0;
    tune_pause = dummy;
    tune_resume = dummy;
}

CEngineAPI::~CEngineAPI()
{
    // destroy quality token here
    if (vid_quality_token)
    {
        xr_free(vid_quality_token);
        vid_quality_token = NULL;
    }
}

extern u32 renderer_value; //con cmd
ENGINE_API int g_current_renderer = 0;

ENGINE_API bool is_enough_address_space_available()
{
    SYSTEM_INFO system_info;
        GetSystemInfo(&system_info);
        return (*(u32*)&system_info.lpMaximumApplicationAddress) > 0x90000000;
}

#ifndef DEDICATED_SERVER

void CEngineAPI::InitializeNotDedicated()
{
    LPCSTR r2_name = "xrRender_R2.dll";
    LPCSTR r3_name = "xrRender_R3.dll";
    LPCSTR r4_name = "xrRender_R4.dll";
    if (psDeviceFlags.test(rsR4))
    {
        // try to initialize R4
        Log("Loading DLL:", r4_name);
        hRender = LoadLibrary(r4_name);
        if (0 == hRender)
        {
            // try to load R1
            Msg("! ...Failed - incompatible hardware/pre-Vista OS.");
            psDeviceFlags.set(rsR2, TRUE);
        }
    }

    if (psDeviceFlags.test(rsR3))
    {
        // try to initialize R3
        Log("Loading DLL:", r3_name);
        hRender = LoadLibrary(r3_name);
        if (0 == hRender)
        {
            // try to load R1
            Msg("! ...Failed - incompatible hardware/pre-Vista OS.");
            psDeviceFlags.set(rsR2, TRUE);
        }
        else
            g_current_renderer = 3;
    }

    if (psDeviceFlags.test(rsR2))
    {
        // try to initialize R2
        psDeviceFlags.set(rsR4, FALSE);
        psDeviceFlags.set(rsR3, FALSE);
        Log("Loading DLL:", r2_name);
        hRender = LoadLibrary(r2_name);
        if (0 == hRender)
        {
            // try to load R1
            Msg("! ...Failed - incompatible hardware.");
        }
        else
            g_current_renderer = 2;
    }
}
#endif // DEDICATED_SERVER

constexpr const char* r2_name = "xrRender_R2";
constexpr const char* r3_name = "xrRender_R3";
constexpr const char* r4_name = "xrRender_R4";


void CEngineAPI::InitializeRenderer()
{
	// If we failed to load render,
	// then try to fallback to lower one.
	/// FX to Xottab-DUTU: Не трогай!
	if (strstr(Core.Params, "-r4"))
		Console->Execute("renderer renderer_r4");
	else if (strstr(Core.Params, "-r3"))
		Console->Execute("renderer renderer_r3");
	else if (strstr(Core.Params, "-r2.5"))
		Console->Execute("renderer renderer_r2.5");
	else if (strstr(Core.Params, "-r2a"))
		Console->Execute("renderer renderer_r2a");
	else if (strstr(Core.Params, "-r2"))
		Console->Execute("renderer renderer_r2");
	else
	{
		CCC_LoadCFG_custom pTmp("renderer ");
		pTmp.Execute(Console->ConfigFile);
	}

	if (psDeviceFlags.test(rsR4))
	{
		// try to initialize R4
		Log("Loading DLL:", r4_name);
		hRender = LoadLibrary(r4_name);
		if (0 == hRender)
		{
			// try to load R1
			Msg("! ...Failed - incompatible hardware/pre-Vista OS.");
			psDeviceFlags.set(rsR3, true);
		}
		else
			g_current_renderer = 4;
	}

	if (psDeviceFlags.test(rsR3))
	{
		// try to initialize R3
		Log("Loading DLL:", r3_name);
		hRender = LoadLibrary(r3_name);
		if (0 == hRender)
		{
			// try to load R1
			Msg("! ...Failed - incompatible hardware/pre-Vista OS.");
			psDeviceFlags.set(rsR2, true);
		}
		else
			g_current_renderer = 3;
	}
	if (psDeviceFlags.test(rsR2) || !hRender)
	{
		// try to initialize R2
		Log("Loading DLL:", r2_name);
		hRender = LoadLibrary(r2_name);
		R_ASSERT2(hRender, "! ...Failed - incompatible hardware.");
		g_current_renderer = 2;
	}
}

void CEngineAPI::Initialize(void)
{
    //////////////////////////////////////////////////////////////////////////
    // render
    LPCSTR r1_name = "xrRender_R1.dll";

	InitializeRenderer();
	if (0 == hRender && vid_quality_token[0].id != -1)
	{
		// if engine failed to load renderer
		// but there is at least one available
		// then try again
		string32 buf;
		xr_sprintf(buf, "renderer %s", vid_quality_token[0].name);
		Console->Execute(buf);

		// Second attempt
		InitializeRenderer();
	}

	if (0 == hRender)
		R_CHK(GetLastError());

	R_ASSERT2(hRender, "Can't load renderer");

	Device.ConnectToRender();

	// game	
	{
		LPCSTR			g_name = "xrGame";
		if (strstr(Core.Params, "-debug_game"))
		{
			g_name = "xrGame_debug";
		}
		Log("Loading DLL:", g_name);
		hGame = LoadLibrary(g_name);
		if (!hGame)	R_CHK(GetLastError());
		R_ASSERT3(hGame, "Game DLL raised exception during loading or there is no game DLL at all", g_name);
		pCreate = (Factory_Create*)GetProcAddress(hGame, "xrFactory_Create");	R_ASSERT(pCreate);
		pDestroy = (Factory_Destroy*)GetProcAddress(hGame, "xrFactory_Destroy");	R_ASSERT(pDestroy);
	}
}

void CEngineAPI::Destroy(void)
{
    if (hGame)				{ FreeLibrary(hGame);	hGame	= nullptr; }
	if (hRender)			{ FreeLibrary(hRender); hRender = nullptr; }
	pCreate					= 0;
	pDestroy				= 0;
	Engine.Event._destroy	();
	XRC.r_clear_compact		();
}

extern "C" {
    typedef bool __cdecl SupportsAdvancedRendering(void);
    typedef bool _declspec(dllexport) SupportsDX10Rendering();
    typedef bool _declspec(dllexport) SupportsDX11Rendering();
};

void CEngineAPI::CreateRendererList()
{
#ifdef DEDICATED_SERVER

    vid_quality_token = xr_alloc<xr_token>(2);

    vid_quality_token[0].id = 0;
    vid_quality_token[0].name = xr_strdup("renderer_r1");

    vid_quality_token[1].id = -1;
    vid_quality_token[1].name = NULL;

#else
    // TODO: ask renderers if they are supported!
    if (vid_quality_token != NULL) return;
    bool bSupports_r2 = false;
    bool bSupports_r2_5 = false;
    bool bSupports_r3 = false;
    bool bSupports_r4 = false;

    LPCSTR r2_name = "xrRender_R2.dll";
    LPCSTR r3_name = "xrRender_R3.dll";
    LPCSTR r4_name = "xrRender_R4.dll";

    if (strstr(Core.Params, "-perfhud_hack"))
    {
        bSupports_r2 = true;
        bSupports_r2_5 = true;
        bSupports_r3 = true;
        bSupports_r4 = true;
    }
    else
    {
        // try to initialize R2
        Log("Loading DLL:", r2_name);
        hRender = LoadLibrary(r2_name);
        if (hRender)
        {
            bSupports_r2 = true;
            SupportsAdvancedRendering* test_rendering = (SupportsAdvancedRendering*)GetProcAddress(hRender, "SupportsAdvancedRendering");
            R_ASSERT(test_rendering);
            bSupports_r2_5 = test_rendering();
            FreeLibrary(hRender);
        }

        // try to initialize R3
        Log("Loading DLL:", r3_name);
        // Hide "d3d10.dll not found" message box for XP
        SetErrorMode(SEM_FAILCRITICALERRORS);
        hRender = LoadLibrary(r3_name);
        // Restore error handling
        SetErrorMode(0);
        if (hRender)
        {
            SupportsDX10Rendering* test_dx10_rendering = (SupportsDX10Rendering*)GetProcAddress(hRender, "SupportsDX10Rendering");
            R_ASSERT(test_dx10_rendering);
            bSupports_r3 = test_dx10_rendering();
            FreeLibrary(hRender);
        }

        // try to initialize R4
        Log("Loading DLL:", r4_name);
        // Hide "d3d10.dll not found" message box for XP
        SetErrorMode(SEM_FAILCRITICALERRORS);
        hRender = LoadLibrary(r4_name);
        // Restore error handling
        SetErrorMode(0);
        if (hRender)
        {
            SupportsDX11Rendering* test_dx11_rendering = (SupportsDX11Rendering*)GetProcAddress(hRender, "SupportsDX11Rendering");
            R_ASSERT(test_dx11_rendering);
            bSupports_r4 = test_dx11_rendering();
            FreeLibrary(hRender);
        }
    }

    hRender = 0;
    bool proceed = true;
    xr_vector<LPCSTR> _tmp;
    _tmp.push_back("renderer_r1");
    if (proceed &= bSupports_r2, proceed)
    {
        _tmp.push_back("renderer_r2a");
        _tmp.push_back("renderer_r2");
    }
    if (proceed &= bSupports_r2_5, proceed)
        _tmp.push_back("renderer_r2.5");
    if (proceed &= bSupports_r3, proceed)
        _tmp.push_back("renderer_r3");
    if (proceed &= bSupports_r4, proceed)
        _tmp.push_back("renderer_r4");
    
	u32 _cnt = _tmp.size() + 1;
    vid_quality_token = xr_alloc<xr_token>(_cnt);

    vid_quality_token[_cnt - 1].id = -1;
    vid_quality_token[_cnt - 1].name = NULL;	 

#ifdef DEBUG
    Msg("Available render modes[%d]:", _tmp.size());
#endif // DEBUG
    for (u32 i = 0; i < _tmp.size(); ++i)
    {
        vid_quality_token[i].id = i;
        vid_quality_token[i].name = _tmp[i];
#ifdef DEBUG
        Msg("[%s]", _tmp[i]);
#endif // DEBUG
    }
#endif //#ifndef DEDICATED_SERVER
}