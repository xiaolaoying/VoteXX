import VoteXX.datatypes
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('VoteXX_auth', '0001_initial'),
        ('VoteXX', '0001_initial'),
        ('VoteXX', '0002_toyelection_voterfile_voter'),
    ]

    operations = [
        migrations.CreateModel(
            name='CastVote',
            fields=[
                ('voter', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='VoteXX.voter')),
                ('vote', models.CharField(max_length=100)),
                ('vote_hash', models.CharField(max_length=100)),
                ('vote_tinyhash', models.CharField(max_length=50, unique=True, null=True)),
                ('cast_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'abstract': False,
            },
            bases=(models.Model, VoteXX.datatypes.LDObjectContainer),
        ),
    ]

