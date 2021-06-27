from django.db.models import FileField
from django.forms import forms
from django.template.defaultfilters import filesizeformat


class RestrictedFileField(FileField):
    """ max_upload_size:
            2.5MB - 2621440
            5MB - 5242880
            10MB - 10485760
            20MB - 20971520
            50MB - 5242880
            100MB 104857600
            250MB - 214958080
            500MB - 429916160
    """

    def __init__(self, *args, **kwargs):
        self.content_types = kwargs.pop("content_types", [])
        self.max_upload_size = kwargs.pop("max_upload_size", [])

        super().__init__(*args, **kwargs)

    def clean(self, *args, **kwargs):
        data = super().clean(*args, **kwargs)
        file = data.file

        try:
            content_type = file.content_type
            if content_type in self.content_types:
                if file.size > self.max_upload_size:
                    raise forms.ValidationError('Please keep filesize under {}. Current filesize {}'
                                                .format(filesizeformat(self.max_upload_size), filesizeformat(file.size)))
            else:
                raise forms.ValidationError('{} is not allowed.'.format(content_type))
        except AttributeError:
            pass
        return data