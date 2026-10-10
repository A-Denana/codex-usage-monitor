use std::sync::OnceLock;

use windows::Win32::Foundation::{COLORREF, RECT};
use windows::Win32::Graphics::Gdi::{
    CreateSolidBrush, DeleteObject, FillRect, GetTextColor, SetTextColor, HBRUSH, HDC,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateIconFromResourceEx, DrawIconEx, DrawTextW, DI_NORMAL, DT_CENTER, DT_SINGLELINE, DT_VCENTER, HICON, LR_DEFAULTCOLOR,
};

use crate::native_interop::Color;

pub const SIZE: i32 = 16;
pub const RIGHT_MARGIN: i32 = 5;

#[derive(Clone, Copy)]
pub enum Provider {
    Claude,
    Codex,
    Zai,
}

pub fn codex_color(is_dark: bool) -> Color {
    Color::from_hex(if is_dark { "#34D399" } else { "#0F8F70" })
}

pub fn zai_color(is_dark: bool) -> Color {
    Color::from_hex(if is_dark { "#B7A2FF" } else { "#7151BC" })
}

pub fn draw(hdc: HDC, x: i32, y: i32, size: i32, provider: Provider) {
    if let Provider::Zai = provider {
        unsafe {
            let mut rect = RECT { left: x, top: y, right: x + size, bottom: y + size };
            let brush = CreateSolidBrush(COLORREF(Color::from_hex("#6D56B7").to_colorref()));
            FillRect(hdc, &rect, brush);
            let _ = DeleteObject(brush);
            let old = GetTextColor(hdc);
            let _ = SetTextColor(hdc, COLORREF(Color::from_hex("#FFFFFF").to_colorref()));
            let mut mark: Vec<u16> = "Z".encode_utf16().collect();
            let _ = DrawTextW(hdc, &mut mark, &mut rect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            let _ = SetTextColor(hdc, old);
        }
        return;
    }
    // These two handles live for the process lifetime. DrawIconEx scales the
    // embedded 64px artwork to the current monitor's DPI without disk access.
    static CLAUDE: OnceLock<isize> = OnceLock::new();
    static CODEX: OnceLock<isize> = OnceLock::new();
    let (cache, png): (&OnceLock<isize>, &[u8]) = match provider {
        Provider::Claude => (&CLAUDE, include_bytes!("icons/providers/claude.png")),
        Provider::Codex => (&CODEX, include_bytes!("icons/providers/openai.png")),
        Provider::Zai => unreachable!(),
    };
    let handle = *cache.get_or_init(|| unsafe {
        CreateIconFromResourceEx(png, true, 0x00030000, 64, 64, LR_DEFAULTCOLOR)
            .map(|icon| icon.0 as isize)
            .unwrap_or(0)
    });
    if handle != 0 {
        unsafe {
            let _ = DrawIconEx(
                hdc,
                x,
                y,
                HICON(handle as *mut _),
                size,
                size,
                0,
                HBRUSH::default(),
                DI_NORMAL,
            );
        }
    }
}
