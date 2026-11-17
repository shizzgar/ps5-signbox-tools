.section .rodata,"a",@progbits

.global media_param_start, media_param_end
media_param_start:
.incbin "param.json"
media_param_end:

.global media_icon_start, media_icon_end
media_icon_start:
.incbin "icon0.png"
media_icon_end:

.section .note.GNU-stack,"",@progbits
