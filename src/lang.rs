use std::ops::Deref;
/* 
mod ca;
mod cn;
mod da;
mod el;
mod eo;
mod es;
mod fa;
mod fr;
mod id;
mod it;
mod ja;
mod ko;
mod kz;
mod nl;
mod ptbr;
mod ro;
mod sl;
mod sq;
mod sr;
mod sv;
mod th;
mod tr;
mod tw;
mod ua;
mod vn;
mod lt;
mod de;
mod hu;
mod pl;
*/
mod cs;
mod sk;
mod en;



pub const LANGS: &[(&str, &str)] = &[
    /*
    ("it", "Italiano"),
    ("fr", "Français"),
    ("de", "Deutsch"),
    ("nl", "Nederlands"),
    ("zh-cn", "简体中文"),
    ("zh-tw", "繁體中文"),
    ("pt", "Português"),
    ("es", "Español"),
    ("hu", "Magyar"),
    ("ru", "Русский"),
    ("id", "Indonesia"),
    ("da", "Dansk"),
    ("eo", "Esperanto"),
    ("tr", "Türkçe"),
    ("vn", "Tiếng Việt"),
    ("pl", "Polski"),
    ("ja", "日本語"),
    ("ko", "한국어"),
    ("kz", "Қазақ"),
    ("ua", "Українська"),
    ("fa", "فارسی"),
    ("ca", "Català"),
    ("el", "Ελληνικά"),
    ("sv", "Svenska"),
    ("sq", "Shqip"),
    ("sr", "Srpski"),
    ("th", "ภาษาไทย"),
    ("sl", "Slovenščina"),
    ("ro", "Română"),
    ("lt", "Lietuvių"),
    */
    ("sk", "Slovenčina"),
    ("cs", "Čeština"),
    ("en", "English"),
];

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn translate(name: String) -> String {
    let locale = sys_locale::get_locale().unwrap_or_default().to_lowercase();
    translate_locale(name, &locale)
}

pub fn translate_locale(name: String, locale: &str) -> String {
    let mut lang = hbb_common::config::LocalConfig::get_option("lang").to_lowercase();
    if lang.is_empty() {
        // zh_CN on Linux, zh-Hans-CN on mac, zh_CN_#Hans on Android
        if locale.starts_with("zh") {
            lang = (if locale.contains("tw") {
                "zh-tw"
            } else {
                "zh-cn"
            })
            .to_owned();
        }
    }
    if lang.is_empty() {
        lang = locale
            .split("-")
            .next()
            .map(|x| x.split("_").next().unwrap_or_default())
            .unwrap_or_default()
            .to_owned();
    }
    let lang = lang.to_lowercase();
    let m = match lang.as_str() {
        /* 
        "fr" => fr::T.deref(),
        "zh-cn" => cn::T.deref(),
        "it" => it::T.deref(),
        "zh-tw" => tw::T.deref(),
        "nl" => nl::T.deref(),
        "es" => es::T.deref(),
        "ru" => ru::T.deref(),
        "eo" => eo::T.deref(),
        "id" => id::T.deref(),
        "br" => ptbr::T.deref(),
        "pt" => ptbr::T.deref(),
        "tr" => tr::T.deref(),
        "da" => da::T.deref(),
        "vn" => vn::T.deref(),
        "ja" => ja::T.deref(),
        "ko" => ko::T.deref(),
        "kz" => kz::T.deref(),
        "ua" => ua::T.deref(),
        "fa" => fa::T.deref(),
        "ca" => ca::T.deref(),
        "el" => el::T.deref(),
        "sv" => sv::T.deref(),
        "sq" => sq::T.deref(),
        "sr" => sr::T.deref(),
        "th" => th::T.deref(),
        "sl" => sl::T.deref(),
        "ro" => ro::T.deref(),
        "lt" => lt::T.deref(),
        "hu" => hu::T.deref(),
        "pl" => pl::T.deref(),
        "de" => de::T.deref(),
        */
        
       
        "sk" => sk::T.deref(),
        "en" => en::T.deref(),
        
        _ => cs::T.deref(),
    };
    if let Some(v) = m.get(&name as &str) {
        if v.is_empty() {
            if lang != "cs" {
                if let Some(v) = cs::T.get(&name as &str) {
                    return v.to_string();
                }
            }
        } else {
            return v.to_string();
        }
    }
    name
}
