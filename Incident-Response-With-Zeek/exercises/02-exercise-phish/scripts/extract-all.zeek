global ext_map: table[string] of string = {
    ["application/x-dosexec"] = "exe",
    ["application/pdf"] = "pdf",
    ["text/plain"] = "txt",
    ["image/jpeg"] = "jpg",
    ["image/png"] = "png",
    ["text/html"] = "html",
    ["*/*"] = "all",
} &default ="";

event file_sniff(f: fa_file, meta: fa_metadata)
    {
    local ext = "";

    if ( meta?$mime_type )
        ext = ext_map[meta$mime_type];

    local fname = fmt("%s-%s.%s", f$source, f$id, ext);
    Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
    }
